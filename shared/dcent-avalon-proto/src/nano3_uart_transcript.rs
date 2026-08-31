// SPDX-License-Identifier: GPL-3.0-or-later
//
// Pure offline validation for timestamped Nano 3 native-UART captures.
//
// This module opens no device, reads no stream, sends no frame, and submits no
// share. It accepts already captured one-frame events and proves their envelope,
// ordering, retry timing, and exact held-stock bytes. Observing a stateful stock
// reset selector is explicitly not authority to reproduce it.

use sha2::{Digest, Sha256};

use crate::nano3_uart::{
    decode_native_uart_envelope, decode_rx_frame, nonce_records, summary_status, Nano3UartError,
    RxFrame, RxType, StockNextPollAction, HEADER_LEN, MAGIC, MAX_FRAME_LEN, MAX_PAYLOAD_LEN,
    STOCK_POLL_ATTEMPT_LIMIT, STOCK_POLL_RESPONSE_TIMEOUT_MS,
};
use crate::nano3_uart_rx::{Nano3RecentJobs, NonceAdmissionError};
use crate::nano3_uart_tx::{
    detect_request, read_only_poll, share_job_snapshot, stock_post_sync_init_trace, sync_request,
    verify_share_candidate, CryptographicallyValidatedNonce, DetectAckContract, JobIdentityCache,
    Nano3ShareError, Nano3ShareJob, Nano3TxError, Nano3TxFrame, Nano3TxResearchCapability,
    StockJobTrace, StockJobTraceInput, STOCK_INIT_ATTEMPT_LIMIT, STOCK_INIT_RESPONSE_TIMEOUT_MS,
};

const INIT_RESPONSE_TIMEOUT_US: u64 = STOCK_INIT_RESPONSE_TIMEOUT_MS as u64 * 1_000;
const POLL_RESPONSE_TIMEOUT_US: u64 = STOCK_POLL_RESPONSE_TIMEOUT_MS as u64 * 1_000;
const CAPTURE_DIGEST_DOMAIN: &[u8] = b"DCENT-NANO3-UART-CAPTURE-V1\0";
const TYPE_POLL: u8 = 0x33;

/// Magic bytes at the start of every portable Nano 3 capture artifact.
pub const CAPTURE_ARTIFACT_MAGIC: [u8; 8] = *b"DCN3CAP\0";

/// Current portable capture artifact version.
pub const CAPTURE_ARTIFACT_VERSION: u16 = 1;

/// Exact fixed header size for capture artifact version 1.
pub const CAPTURE_ARTIFACT_HEADER_LEN: usize = 64;

/// Exact per-event metadata size before one complete CN frame.
pub const CAPTURE_ARTIFACT_EVENT_HEADER_LEN: usize = 16;

/// Hard allocation and parsing ceiling for one capture artifact.
pub const CAPTURE_ARTIFACT_MAX_EVENTS: usize = 4_096;

/// Maximum canonical byte length of one capture artifact.
pub const CAPTURE_ARTIFACT_MAX_LEN: usize = CAPTURE_ARTIFACT_HEADER_LEN
    + CAPTURE_ARTIFACT_MAX_EVENTS * (CAPTURE_ARTIFACT_EVENT_HEADER_LEN + MAX_FRAME_LEN);

/// Maximum raw frame bytes accepted by the offline chunk assembler.
pub const CAPTURE_ASSEMBLY_MAX_RAW_BYTES: usize = CAPTURE_ARTIFACT_MAX_EVENTS * MAX_FRAME_LEN;

/// Maximum nonempty byte chunks accepted by the offline assembler.
///
/// This equals the raw-byte ceiling so an external producer may supply one
/// timestamped byte per chunk without creating an unbounded metadata path.
pub const CAPTURE_ASSEMBLY_MAX_CHUNKS: usize = CAPTURE_ASSEMBLY_MAX_RAW_BYTES;

const ARTIFACT_VERSION_OFFSET: usize = 8;
const ARTIFACT_HEADER_LEN_OFFSET: usize = 10;
const ARTIFACT_EVENT_COUNT_OFFSET: usize = 12;
const ARTIFACT_ENDED_US_OFFSET: usize = 16;
const ARTIFACT_DIGEST_OFFSET: usize = 24;
const ARTIFACT_DIGEST_END: usize = ARTIFACT_DIGEST_OFFSET + 32;
const ARTIFACT_HEADER_RESERVED_OFFSET: usize = ARTIFACT_DIGEST_END;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureDirection {
    HostToController,
    ControllerToHost,
}

impl CaptureDirection {
    const fn canonical_byte(self) -> u8 {
        match self {
            Self::HostToController => 0,
            Self::ControllerToHost => 1,
        }
    }
}

/// One already captured, timestamped frame.
///
/// `bytes` must contain exactly one complete frame. The timestamp is elapsed
/// microseconds from a capture-local monotonic clock, not wall time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureEvent<'a> {
    pub elapsed_us: u64,
    pub direction: CaptureDirection,
    pub bytes: &'a [u8],
}

/// One nonempty direction-tagged chunk from an external offline capture.
///
/// `elapsed_us` is the monotonic timestamp of the chunk's final byte. Use
/// one-byte chunks when the capture source provides per-byte timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureByteChunk<'a> {
    pub elapsed_us: u64,
    pub direction: CaptureDirection,
    pub bytes: &'a [u8],
}

/// A bounded capture slice plus the monotonic time at which capture stopped.
///
/// The explicit end time proves that a final missing response was actually
/// observed through the complete timeout rather than truncated immediately
/// after the last TX frame.
#[derive(Debug, Clone, Copy)]
pub struct CaptureWindow<'events, 'bytes> {
    pub events: &'events [CaptureEvent<'bytes>],
    pub ended_us: u64,
}

impl<'events, 'bytes> CaptureWindow<'events, 'bytes> {
    pub const fn new(events: &'events [CaptureEvent<'bytes>], ended_us: u64) -> Self {
        Self { events, ended_us }
    }
}

/// A strictly decoded portable capture artifact borrowing its frame bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "decoded capture evidence grants no device or transmit authority"]
pub struct DecodedCaptureArtifact<'bytes> {
    events: Vec<CaptureEvent<'bytes>>,
    ended_us: u64,
    digest: [u8; 32],
}

impl<'bytes> DecodedCaptureArtifact<'bytes> {
    pub fn events(&self) -> &[CaptureEvent<'bytes>] {
        &self.events
    }

    pub const fn ended_us(&self) -> u64 {
        self.ended_us
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn window(&self) -> CaptureWindow<'_, 'bytes> {
        CaptureWindow::new(&self.events, self.ended_us)
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Nano3CaptureArtifactError {
    #[error("Nano 3 capture artifact has {observed} bytes, below header size {minimum}")]
    TooShort { observed: usize, minimum: usize },

    #[error("Nano 3 capture artifact has {observed} bytes, above limit {maximum}")]
    TooLong { observed: usize, maximum: usize },

    #[error("Nano 3 capture artifact has invalid magic {0:02x?}")]
    BadMagic([u8; 8]),

    #[error("unsupported Nano 3 capture artifact version {0}")]
    UnsupportedVersion(u16),

    #[error(
        "Nano 3 capture artifact header length {observed} is not canonical version-1 length {expected}"
    )]
    NonCanonicalHeaderLength { observed: u16, expected: usize },

    #[error("Nano 3 capture artifact contains {observed} events, above limit {maximum}")]
    TooManyEvents { observed: usize, maximum: usize },

    #[error("Nano 3 capture artifact extraction requires at least one event")]
    EmptySelection,

    #[error(
        "Nano 3 capture artifact extraction starts at event {first_event}, but only {available} event(s) exist"
    )]
    SelectionStartOutOfRange {
        first_event: usize,
        available: usize,
    },

    #[error(
        "Nano 3 capture artifact extraction range first={first_event} count={event_count} exceeds {available} event(s)"
    )]
    SelectionEndOutOfRange {
        first_event: usize,
        event_count: usize,
        available: usize,
    },

    #[error(
        "Nano 3 capture artifact extraction cannot place an end boundary between event {last_event} at {last_event_us} us and event {next_event} at {next_event_us} us"
    )]
    IndistinguishableSelectionBoundary {
        last_event: usize,
        last_event_us: u64,
        next_event: usize,
        next_event_us: u64,
    },

    #[error("Nano 3 capture artifact header reserved bytes are nonzero")]
    NonZeroHeaderReserved,

    #[error(
        "Nano 3 capture artifact event {event_index} header is truncated: {remaining} bytes remain"
    )]
    TruncatedEventHeader {
        event_index: usize,
        remaining: usize,
    },

    #[error("Nano 3 capture artifact event {event_index} direction {observed} is invalid")]
    InvalidDirection { event_index: usize, observed: u8 },

    #[error("Nano 3 capture artifact event {event_index} flags byte is nonzero")]
    NonZeroEventFlags { event_index: usize },

    #[error("Nano 3 capture artifact event {event_index} reserved bytes are nonzero")]
    NonZeroEventReserved { event_index: usize },

    #[error(
        "Nano 3 capture artifact event {event_index} frame is truncated: declared {declared}, available {available}"
    )]
    TruncatedFrame {
        event_index: usize,
        declared: usize,
        available: usize,
    },

    #[error("Nano 3 capture artifact event {event_index} has an invalid CN frame: {source}")]
    Envelope {
        event_index: usize,
        source: Nano3UartError,
    },

    #[error("Nano 3 capture artifact has {0} trailing byte(s)")]
    TrailingBytes(usize),

    #[error(
        "Nano 3 capture artifact digest mismatch: declared {declared:02x?}, calculated {calculated:02x?}"
    )]
    DigestMismatch {
        declared: [u8; 32],
        calculated: [u8; 32],
    },

    #[error("Nano 3 capture artifact violates the logical transcript contract: {source}")]
    Transcript {
        #[from]
        source: Nano3TranscriptError,
    },
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Nano3CaptureAssemblyError {
    #[error("Nano 3 raw capture contains no chunks")]
    EmptyInput,

    #[error("Nano 3 raw capture contains {observed} chunks, above limit {maximum}")]
    TooManyChunks { observed: usize, maximum: usize },

    #[error("Nano 3 raw capture chunk {chunk_index} is empty")]
    EmptyChunk { chunk_index: usize },

    #[error(
        "Nano 3 raw capture chunk {chunk_index} moves backward in monotonic time: {previous_us} -> {observed_us} us"
    )]
    NonMonotonicChunk {
        chunk_index: usize,
        previous_us: u64,
        observed_us: u64,
    },

    #[error("Nano 3 raw capture contains more than {maximum} frame bytes")]
    TooManyRawBytes { maximum: usize },

    #[error(
        "Nano 3 raw capture chunk {chunk_index} byte {byte_offset} ({direction:?}) has 0x{observed:02x} at frame offset {frame_offset}, expected 0x{expected:02x}"
    )]
    UnexpectedFrameByte {
        chunk_index: usize,
        byte_offset: usize,
        direction: CaptureDirection,
        frame_offset: usize,
        expected: u8,
        observed: u8,
    },

    #[error(
        "Nano 3 raw capture chunk {chunk_index} byte {byte_offset} ({direction:?}) completes an invalid CN frame: {source}"
    )]
    Envelope {
        chunk_index: usize,
        byte_offset: usize,
        direction: CaptureDirection,
        source: Nano3UartError,
    },

    #[error("Nano 3 raw capture contains more than {maximum} complete frames")]
    TooManyEvents { maximum: usize },

    #[error(
        "Nano 3 raw capture ends with an incomplete {direction:?} frame: {buffered} bytes buffered, expected total {expected:?}"
    )]
    IncompleteFrame {
        direction: CaptureDirection,
        buffered: usize,
        expected: Option<usize>,
    },

    #[error(
        "Nano 3 raw capture ended at {ended_us} us before its last chunk at {last_chunk_us} us"
    )]
    EndBeforeLastChunk { ended_us: u64, last_chunk_us: u64 },

    #[error("Nano 3 raw capture could not produce a canonical artifact: {source}")]
    Artifact {
        #[from]
        source: Nano3CaptureArtifactError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangePhase {
    Detect,
    Sync,
    Poll,
    Nonce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedPollSelector {
    ReadOnly,
    StatefulReset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollCaptureOutcome {
    Response {
        packet_type: RxType,
        next_stock_action: Option<StockNextPollAction>,
    },
    ExhaustedWithoutResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "validated capture evidence grants no transmit or device authority"]
pub struct ValidatedInitCapture {
    detect_attempts: u8,
    sync_attempts: u8,
    detected_work_level_maximum: u8,
    selected_work_level: u8,
    digest: [u8; 32],
}

impl ValidatedInitCapture {
    pub const fn detect_attempts(&self) -> u8 {
        self.detect_attempts
    }

    pub const fn sync_attempts(&self) -> u8 {
        self.sync_attempts
    }

    pub const fn detected_work_level_maximum(&self) -> u8 {
        self.detected_work_level_maximum
    }

    pub const fn selected_work_level(&self) -> u8 {
        self.selected_work_level
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "validated capture evidence grants no transmit or device authority"]
pub struct ValidatedJobCapture {
    frame_count: usize,
    emitted_identity: bool,
    next_identity_cache: JobIdentityCache,
    share_job: Nano3ShareJob,
    digest: [u8; 32],
}

impl ValidatedJobCapture {
    pub const fn frame_count(&self) -> usize {
        self.frame_count
    }

    pub const fn emitted_identity(&self) -> bool {
        self.emitted_identity
    }

    pub const fn next_identity_cache(&self) -> JobIdentityCache {
        self.next_identity_cache
    }

    /// Immutable share-reconstruction material proven to match this capture.
    pub const fn share_job(&self) -> &Nano3ShareJob {
        &self.share_job
    }

    pub fn into_share_job(self) -> Nano3ShareJob {
        self.share_job
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "observing a stock poll grants no authority to reproduce it"]
pub struct ValidatedPollCapture {
    selector: ObservedPollSelector,
    attempts: u8,
    outcome: PollCaptureOutcome,
    digest: [u8; 32],
}

impl ValidatedPollCapture {
    pub const fn selector(&self) -> ObservedPollSelector {
        self.selector
    }

    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    pub const fn outcome(&self) -> PollCaptureOutcome {
        self.outcome
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// This result is evidence only, including for an observed selector 1.
    pub const fn authorizes_transmit(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "validated nonce evidence grants no share-submission authority"]
pub struct ValidatedNonceCapture {
    nonces: Vec<CryptographicallyValidatedNonce>,
    digest: [u8; 32],
}

impl ValidatedNonceCapture {
    pub fn nonces(&self) -> &[CryptographicallyValidatedNonce] {
        &self.nonces
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Nano3TranscriptError {
    #[error("Nano 3 capture contains no events")]
    EmptyCapture,

    #[error(
        "Nano 3 capture event {event_index} moves backward in monotonic time: {previous_us} -> {observed_us} us"
    )]
    NonMonotonicTime {
        event_index: usize,
        previous_us: u64,
        observed_us: u64,
    },

    #[error("Nano 3 capture ended at {ended_us} us before its last event at {last_event_us} us")]
    EndBeforeLastEvent { ended_us: u64, last_event_us: u64 },

    #[error("Nano 3 capture is missing event {event_index} ({expected})")]
    MissingEvent {
        event_index: usize,
        expected: &'static str,
    },

    #[error(
        "Nano 3 capture event {event_index} has direction {observed:?}, expected {expected:?}"
    )]
    UnexpectedDirection {
        event_index: usize,
        expected: CaptureDirection,
        observed: CaptureDirection,
    },

    #[error("Nano 3 capture event {event_index} has an invalid envelope: {source}")]
    Envelope {
        event_index: usize,
        source: Nano3UartError,
    },

    #[error(
        "Nano 3 capture TX event {event_index} does not match the exact expected type 0x{expected_type:02x} frame (observed type 0x{observed_type:02x})"
    )]
    TxFrameMismatch {
        event_index: usize,
        expected_type: u8,
        observed_type: u8,
    },

    #[error(
        "Nano 3 {phase:?} response at event {event_index} has type 0x{observed:02x}, expected 0x{expected:02x}"
    )]
    UnexpectedResponseType {
        phase: ExchangePhase,
        event_index: usize,
        expected: u8,
        observed: u8,
    },

    #[error(
        "Nano 3 {phase:?} response attempt {attempt} took {elapsed_us} us, above {maximum_us} us"
    )]
    ResponseTooLate {
        phase: ExchangePhase,
        attempt: u8,
        elapsed_us: u64,
        maximum_us: u64,
    },

    #[error(
        "Nano 3 {phase:?} retry attempt {attempt} started after {elapsed_us} us, below the {minimum_us} us timeout"
    )]
    RetryTooEarly {
        phase: ExchangePhase,
        attempt: u8,
        elapsed_us: u64,
        minimum_us: u64,
    },

    #[error("Nano 3 {phase:?} capture exceeds stock's {maximum}-attempt limit")]
    TooManyAttempts { phase: ExchangePhase, maximum: u8 },

    #[error(
        "Nano 3 {phase:?} capture ended after {attempts} attempt(s) without a response or the complete stock retry sequence"
    )]
    IncompleteExchange { phase: ExchangePhase, attempts: u8 },

    #[error(
        "Nano 3 capture ended {observed_us} us after the last {phase:?} TX, below the required {minimum_us} us timeout"
    )]
    CaptureEndedBeforeTimeout {
        phase: ExchangePhase,
        observed_us: u64,
        minimum_us: u64,
    },

    #[error("Nano 3 capture has {count} trailing event(s) beginning at event {event_index}")]
    TrailingEvents { event_index: usize, count: usize },

    #[error("Nano 3 init capture violates the held TX contract: {source}")]
    InitContract { source: Nano3TxError },

    #[error("Nano 3 job capture violates the held TX contract: {source}")]
    JobContract { source: Nano3TxError },

    #[error("Nano 3 job capture frame count mismatch: expected {expected}, observed {observed}")]
    JobFrameCountMismatch { expected: usize, observed: usize },

    #[error(
        "Nano 3 poll event {event_index} has unsupported header type=0x{packet_type:02x} option={option} index={index} count={count} payload_len={payload_len}"
    )]
    UnsupportedPollHeader {
        event_index: usize,
        packet_type: u8,
        option: u8,
        index: u16,
        count: u16,
        payload_len: usize,
    },

    #[error("Nano 3 poll event {event_index} carries unsupported selector bytes {selector:02x?}")]
    UnsupportedPollSelector {
        event_index: usize,
        selector: [u8; 4],
    },

    #[error("Nano 3 poll retry event {event_index} differs from the first observed request")]
    PollRetryChanged { event_index: usize },

    #[error("Nano 3 nonce capture contains no nonce records")]
    EmptyNonceBatch,

    #[error("Nano 3 nonce record {record_index} failed structural admission: {source}")]
    NonceAdmission {
        record_index: usize,
        source: NonceAdmissionError,
    },

    #[error("Nano 3 nonce record {record_index} failed cryptographic validation: {source}")]
    ShareValidation {
        record_index: usize,
        source: Nano3ShareError,
    },
}

/// Canonical SHA-256 over capture end time, direction, timestamps, lengths,
/// and exact frame bytes. This binds evidence; it grants no device authority.
pub fn transcript_sha256(window: CaptureWindow<'_, '_>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CAPTURE_DIGEST_DOMAIN);
    hasher.update(window.ended_us.to_le_bytes());
    hasher.update((window.events.len() as u64).to_le_bytes());
    for event in window.events {
        hasher.update([event.direction.canonical_byte()]);
        hasher.update(event.elapsed_us.to_le_bytes());
        hasher.update((event.bytes.len() as u64).to_le_bytes());
        hasher.update(event.bytes);
    }
    hasher.finalize().into()
}

/// Encode one validated logical capture into the canonical portable artifact.
///
/// This performs no I/O. Every event must already contain exactly one valid CN
/// frame, and the resulting bytes grant no device or transmit authority.
pub fn encode_capture_artifact(
    window: CaptureWindow<'_, '_>,
) -> Result<Vec<u8>, Nano3CaptureArtifactError> {
    validate_capture_clock(window)?;
    if window.events.len() > CAPTURE_ARTIFACT_MAX_EVENTS {
        return Err(Nano3CaptureArtifactError::TooManyEvents {
            observed: window.events.len(),
            maximum: CAPTURE_ARTIFACT_MAX_EVENTS,
        });
    }

    let mut encoded_len = CAPTURE_ARTIFACT_HEADER_LEN;
    for (event_index, event) in window.events.iter().enumerate() {
        decode_native_uart_envelope(event.bytes).map_err(|source| {
            Nano3CaptureArtifactError::Envelope {
                event_index,
                source,
            }
        })?;
        encoded_len += CAPTURE_ARTIFACT_EVENT_HEADER_LEN + event.bytes.len();
    }
    debug_assert!(encoded_len <= CAPTURE_ARTIFACT_MAX_LEN);

    let digest = transcript_sha256(window);
    let mut bytes = Vec::with_capacity(encoded_len);
    bytes.extend_from_slice(&CAPTURE_ARTIFACT_MAGIC);
    bytes.extend_from_slice(&CAPTURE_ARTIFACT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(CAPTURE_ARTIFACT_HEADER_LEN as u16).to_le_bytes());
    bytes.extend_from_slice(&(window.events.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&window.ended_us.to_le_bytes());
    bytes.extend_from_slice(&digest);
    bytes.extend_from_slice(&[0; 8]);
    debug_assert_eq!(bytes.len(), CAPTURE_ARTIFACT_HEADER_LEN);

    for event in window.events {
        bytes.extend_from_slice(&event.elapsed_us.to_le_bytes());
        bytes.push(event.direction.canonical_byte());
        bytes.push(0);
        bytes.extend_from_slice(&(event.bytes.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(event.bytes);
    }
    debug_assert_eq!(bytes.len(), encoded_len);
    Ok(bytes)
}

/// Extract a contiguous event range into a new canonical capture artifact.
///
/// When the range reaches the final source event, the source capture end is
/// preserved. Otherwise the new end is exactly the final retained event time.
/// Frame-completion timestamps cannot prove when the next excluded frame began,
/// so a non-final extraction deliberately preserves no post-event silence and
/// cannot manufacture timeout evidence. Equal-microsecond boundaries are
/// refused because version 1 cannot distinguish an excluded event at the same
/// capture time. Timestamps are not rebased, and the result grants no device or
/// transmit authority.
pub fn extract_capture_artifact(
    window: CaptureWindow<'_, '_>,
    first_event: usize,
    event_count: usize,
) -> Result<Vec<u8>, Nano3CaptureArtifactError> {
    validate_capture_clock(window)?;
    if event_count == 0 {
        return Err(Nano3CaptureArtifactError::EmptySelection);
    }
    if first_event >= window.events.len() {
        return Err(Nano3CaptureArtifactError::SelectionStartOutOfRange {
            first_event,
            available: window.events.len(),
        });
    }
    let end = first_event.checked_add(event_count).ok_or(
        Nano3CaptureArtifactError::SelectionEndOutOfRange {
            first_event,
            event_count,
            available: window.events.len(),
        },
    )?;
    if end > window.events.len() {
        return Err(Nano3CaptureArtifactError::SelectionEndOutOfRange {
            first_event,
            event_count,
            available: window.events.len(),
        });
    }

    let selected = &window.events[first_event..end];
    let ended_us = if end == window.events.len() {
        window.ended_us
    } else {
        let last_event = end - 1;
        let last_event_us = selected
            .last()
            .expect("nonempty selection checked above")
            .elapsed_us;
        let next_event_us = window.events[end].elapsed_us;
        if next_event_us <= last_event_us {
            return Err(
                Nano3CaptureArtifactError::IndistinguishableSelectionBoundary {
                    last_event,
                    last_event_us,
                    next_event: end,
                    next_event_us,
                },
            );
        }
        last_event_us
    };

    encode_capture_artifact(CaptureWindow::new(selected, ended_us))
}

/// Decode a canonical portable capture artifact without copying frame bytes.
///
/// Parsing is capped at [`CAPTURE_ARTIFACT_MAX_EVENTS`], validates every CN
/// envelope, rejects all non-canonical reserved/trailing bytes, re-checks the
/// logical clock, and verifies the embedded transcript digest.
pub fn decode_capture_artifact(
    bytes: &[u8],
) -> Result<DecodedCaptureArtifact<'_>, Nano3CaptureArtifactError> {
    if bytes.len() < CAPTURE_ARTIFACT_HEADER_LEN {
        return Err(Nano3CaptureArtifactError::TooShort {
            observed: bytes.len(),
            minimum: CAPTURE_ARTIFACT_HEADER_LEN,
        });
    }
    if bytes.len() > CAPTURE_ARTIFACT_MAX_LEN {
        return Err(Nano3CaptureArtifactError::TooLong {
            observed: bytes.len(),
            maximum: CAPTURE_ARTIFACT_MAX_LEN,
        });
    }

    let magic: [u8; 8] = bytes[..8].try_into().expect("checked artifact header");
    if magic != CAPTURE_ARTIFACT_MAGIC {
        return Err(Nano3CaptureArtifactError::BadMagic(magic));
    }
    let version = u16_at(bytes, ARTIFACT_VERSION_OFFSET);
    if version != CAPTURE_ARTIFACT_VERSION {
        return Err(Nano3CaptureArtifactError::UnsupportedVersion(version));
    }
    let header_len = u16_at(bytes, ARTIFACT_HEADER_LEN_OFFSET);
    if usize::from(header_len) != CAPTURE_ARTIFACT_HEADER_LEN {
        return Err(Nano3CaptureArtifactError::NonCanonicalHeaderLength {
            observed: header_len,
            expected: CAPTURE_ARTIFACT_HEADER_LEN,
        });
    }
    let event_count = u32_at(bytes, ARTIFACT_EVENT_COUNT_OFFSET) as usize;
    if event_count > CAPTURE_ARTIFACT_MAX_EVENTS {
        return Err(Nano3CaptureArtifactError::TooManyEvents {
            observed: event_count,
            maximum: CAPTURE_ARTIFACT_MAX_EVENTS,
        });
    }
    let ended_us = u64_at(bytes, ARTIFACT_ENDED_US_OFFSET);
    let declared_digest: [u8; 32] = bytes[ARTIFACT_DIGEST_OFFSET..ARTIFACT_DIGEST_END]
        .try_into()
        .expect("checked artifact header");
    if bytes[ARTIFACT_HEADER_RESERVED_OFFSET..CAPTURE_ARTIFACT_HEADER_LEN]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Nano3CaptureArtifactError::NonZeroHeaderReserved);
    }

    let mut cursor = CAPTURE_ARTIFACT_HEADER_LEN;
    let mut events = Vec::with_capacity(event_count);
    for event_index in 0..event_count {
        let remaining = bytes.len() - cursor;
        if remaining < CAPTURE_ARTIFACT_EVENT_HEADER_LEN {
            return Err(Nano3CaptureArtifactError::TruncatedEventHeader {
                event_index,
                remaining,
            });
        }
        let event_header = &bytes[cursor..cursor + CAPTURE_ARTIFACT_EVENT_HEADER_LEN];
        let elapsed_us = u64_at(event_header, 0);
        let direction = match event_header[8] {
            0 => CaptureDirection::HostToController,
            1 => CaptureDirection::ControllerToHost,
            observed => {
                return Err(Nano3CaptureArtifactError::InvalidDirection {
                    event_index,
                    observed,
                })
            }
        };
        if event_header[9] != 0 {
            return Err(Nano3CaptureArtifactError::NonZeroEventFlags { event_index });
        }
        let frame_len = usize::from(u16_at(event_header, 10));
        if event_header[12..16].iter().any(|byte| *byte != 0) {
            return Err(Nano3CaptureArtifactError::NonZeroEventReserved { event_index });
        }
        cursor += CAPTURE_ARTIFACT_EVENT_HEADER_LEN;
        let available = bytes.len() - cursor;
        if frame_len > available {
            return Err(Nano3CaptureArtifactError::TruncatedFrame {
                event_index,
                declared: frame_len,
                available,
            });
        }
        let frame_bytes = &bytes[cursor..cursor + frame_len];
        decode_native_uart_envelope(frame_bytes).map_err(|source| {
            Nano3CaptureArtifactError::Envelope {
                event_index,
                source,
            }
        })?;
        events.push(CaptureEvent {
            elapsed_us,
            direction,
            bytes: frame_bytes,
        });
        cursor += frame_len;
    }
    if cursor != bytes.len() {
        return Err(Nano3CaptureArtifactError::TrailingBytes(
            bytes.len() - cursor,
        ));
    }

    let window = CaptureWindow::new(&events, ended_us);
    validate_capture_clock(window)?;
    let calculated = transcript_sha256(window);
    if declared_digest != calculated {
        return Err(Nano3CaptureArtifactError::DigestMismatch {
            declared: declared_digest,
            calculated,
        });
    }
    Ok(DecodedCaptureArtifact {
        events,
        ended_us,
        digest: calculated,
    })
}

/// Assemble external direction-tagged byte chunks into a canonical artifact.
///
/// This is a strict offline evidence path, not a live stream resynchronizer.
/// It discards no noise, repairs no corrupt frame, opens no device, and performs
/// no I/O. A frame timestamp is the timestamp of the chunk containing its final
/// byte; use one-byte chunks when finer capture timing is required.
pub fn assemble_capture_artifact(
    chunks: &[CaptureByteChunk<'_>],
    ended_us: u64,
) -> Result<Vec<u8>, Nano3CaptureAssemblyError> {
    if chunks.is_empty() {
        return Err(Nano3CaptureAssemblyError::EmptyInput);
    }
    if chunks.len() > CAPTURE_ASSEMBLY_MAX_CHUNKS {
        return Err(Nano3CaptureAssemblyError::TooManyChunks {
            observed: chunks.len(),
            maximum: CAPTURE_ASSEMBLY_MAX_CHUNKS,
        });
    }

    let mut host_decoder = StrictCapturedFrameDecoder::new();
    let mut controller_decoder = StrictCapturedFrameDecoder::new();
    let mut owned_events = Vec::new();
    let mut total_raw_bytes = 0usize;
    let mut previous_us = None;

    for (chunk_index, chunk) in chunks.iter().enumerate() {
        if chunk.bytes.is_empty() {
            return Err(Nano3CaptureAssemblyError::EmptyChunk { chunk_index });
        }
        if let Some(previous_us) = previous_us {
            if chunk.elapsed_us < previous_us {
                return Err(Nano3CaptureAssemblyError::NonMonotonicChunk {
                    chunk_index,
                    previous_us,
                    observed_us: chunk.elapsed_us,
                });
            }
        }
        previous_us = Some(chunk.elapsed_us);
        total_raw_bytes = total_raw_bytes
            .checked_add(chunk.bytes.len())
            .filter(|total| *total <= CAPTURE_ASSEMBLY_MAX_RAW_BYTES)
            .ok_or(Nano3CaptureAssemblyError::TooManyRawBytes {
                maximum: CAPTURE_ASSEMBLY_MAX_RAW_BYTES,
            })?;

        let decoder = match chunk.direction {
            CaptureDirection::HostToController => &mut host_decoder,
            CaptureDirection::ControllerToHost => &mut controller_decoder,
        };
        for (byte_offset, byte) in chunk.bytes.iter().copied().enumerate() {
            let completed = decoder.push_byte(byte).map_err(|source| match source {
                StrictCapturedFrameError::UnexpectedByte {
                    frame_offset,
                    expected,
                    observed,
                } => Nano3CaptureAssemblyError::UnexpectedFrameByte {
                    chunk_index,
                    byte_offset,
                    direction: chunk.direction,
                    frame_offset,
                    expected,
                    observed,
                },
                StrictCapturedFrameError::Envelope(source) => Nano3CaptureAssemblyError::Envelope {
                    chunk_index,
                    byte_offset,
                    direction: chunk.direction,
                    source,
                },
            })?;
            if let Some(bytes) = completed {
                if owned_events.len() == CAPTURE_ARTIFACT_MAX_EVENTS {
                    return Err(Nano3CaptureAssemblyError::TooManyEvents {
                        maximum: CAPTURE_ARTIFACT_MAX_EVENTS,
                    });
                }
                owned_events.push(OwnedCaptureEvent {
                    elapsed_us: chunk.elapsed_us,
                    direction: chunk.direction,
                    bytes,
                });
            }
        }
    }

    let last_chunk_us = previous_us.expect("nonempty chunks checked above");
    if ended_us < last_chunk_us {
        return Err(Nano3CaptureAssemblyError::EndBeforeLastChunk {
            ended_us,
            last_chunk_us,
        });
    }
    for (direction, decoder) in [
        (CaptureDirection::HostToController, &host_decoder),
        (CaptureDirection::ControllerToHost, &controller_decoder),
    ] {
        if decoder.buffered != 0 {
            return Err(Nano3CaptureAssemblyError::IncompleteFrame {
                direction,
                buffered: decoder.buffered,
                expected: decoder.expected,
            });
        }
    }

    let events: Vec<_> = owned_events
        .iter()
        .map(|event| CaptureEvent {
            elapsed_us: event.elapsed_us,
            direction: event.direction,
            bytes: &event.bytes,
        })
        .collect();
    encode_capture_artifact(CaptureWindow::new(&events, ended_us)).map_err(Into::into)
}

pub fn validate_init_capture(
    window: CaptureWindow<'_, '_>,
    requested_work_level: u8,
) -> Result<ValidatedInitCapture, Nano3TranscriptError> {
    validate_capture_clock(window)?;
    let capability = offline_validation_capability();

    let detect_tx = detect_request(&capability);
    let (cursor, detect_ack, detect_attempts) = validate_retry_exchange(
        window.events,
        0,
        &detect_tx,
        RxType::DetectAck,
        ExchangePhase::Detect,
        STOCK_INIT_ATTEMPT_LIMIT,
        INIT_RESPONSE_TIMEOUT_US,
    )?;
    let detect = DetectAckContract::try_from_detect_ack(&detect_ack)
        .map_err(|source| Nano3TranscriptError::InitContract { source })?;

    let sync_tx = sync_request(&capability, detect.sync_identity());
    let (mut cursor, sync_ack, sync_attempts) = validate_retry_exchange(
        window.events,
        cursor,
        &sync_tx,
        RxType::SyncAck,
        ExchangePhase::Sync,
        STOCK_INIT_ATTEMPT_LIMIT,
        INIT_RESPONSE_TIMEOUT_US,
    )?;
    let post_sync =
        stock_post_sync_init_trace(&capability, detect, &sync_ack, requested_work_level)
            .map_err(|source| Nano3TranscriptError::InitContract { source })?;
    for frame in &post_sync {
        expect_exact_tx(window.events, cursor, frame)?;
        cursor += 1;
    }
    require_consumed(window.events, cursor)?;

    let maximum = detect.work_level_maximum().value();
    let selected_work_level = if requested_work_level < maximum {
        requested_work_level
    } else {
        1
    };
    Ok(ValidatedInitCapture {
        detect_attempts,
        sync_attempts,
        detected_work_level_maximum: maximum,
        selected_work_level,
        digest: transcript_sha256(window),
    })
}

pub fn validate_job_capture(
    window: CaptureWindow<'_, '_>,
    previous_identity: JobIdentityCache,
    input: StockJobTraceInput<'_>,
) -> Result<ValidatedJobCapture, Nano3TranscriptError> {
    validate_capture_clock(window)?;
    let (expected, share_job) = paired_job_trace_and_snapshot(previous_identity, input)
        .map_err(|source| Nano3TranscriptError::JobContract { source })?;
    if window.events.len() != expected.frames().len() {
        return Err(Nano3TranscriptError::JobFrameCountMismatch {
            expected: expected.frames().len(),
            observed: window.events.len(),
        });
    }
    for (event_index, frame) in expected.frames().iter().enumerate() {
        expect_exact_tx(window.events, event_index, frame)?;
    }
    Ok(ValidatedJobCapture {
        frame_count: expected.frames().len(),
        emitted_identity: expected.emitted_identity(),
        next_identity_cache: expected.next_identity_cache(),
        share_job,
        digest: transcript_sha256(window),
    })
}

pub fn validate_poll_capture(
    window: CaptureWindow<'_, '_>,
) -> Result<ValidatedPollCapture, Nano3TranscriptError> {
    validate_capture_clock(window)?;
    let capability = offline_validation_capability();
    let first = window
        .events
        .first()
        .ok_or(Nano3TranscriptError::EmptyCapture)?;
    expect_direction(first, 0, CaptureDirection::HostToController)?;
    let selector = decode_poll_selector(first.bytes, 0)?;
    if selector == ObservedPollSelector::ReadOnly
        && first.bytes != read_only_poll(&capability).as_bytes()
    {
        let observed_type = decode_envelope_at(first, 0)?.packet_type;
        return Err(Nano3TranscriptError::TxFrameMismatch {
            event_index: 0,
            expected_type: TYPE_POLL,
            observed_type,
        });
    }

    let first_bytes = first.bytes;
    let mut cursor = 0usize;
    let mut attempts = 0u8;
    loop {
        let event = window
            .events
            .get(cursor)
            .ok_or(Nano3TranscriptError::MissingEvent {
                event_index: cursor,
                expected: "poll request",
            })?;
        expect_direction(event, cursor, CaptureDirection::HostToController)?;
        let observed_selector = decode_poll_selector(event.bytes, cursor)?;
        if observed_selector != selector || event.bytes != first_bytes {
            return Err(Nano3TranscriptError::PollRetryChanged {
                event_index: cursor,
            });
        }
        attempts += 1;
        let sent_at = event.elapsed_us;
        cursor += 1;

        let Some(next) = window.events.get(cursor) else {
            if attempts != STOCK_POLL_ATTEMPT_LIMIT {
                return Err(Nano3TranscriptError::IncompleteExchange {
                    phase: ExchangePhase::Poll,
                    attempts,
                });
            }
            let observed_us = window.ended_us - sent_at;
            if observed_us < POLL_RESPONSE_TIMEOUT_US {
                return Err(Nano3TranscriptError::CaptureEndedBeforeTimeout {
                    phase: ExchangePhase::Poll,
                    observed_us,
                    minimum_us: POLL_RESPONSE_TIMEOUT_US,
                });
            }
            return Ok(ValidatedPollCapture {
                selector,
                attempts,
                outcome: PollCaptureOutcome::ExhaustedWithoutResponse,
                digest: transcript_sha256(window),
            });
        };

        let elapsed_us = next.elapsed_us - sent_at;
        match next.direction {
            CaptureDirection::ControllerToHost => {
                if elapsed_us > POLL_RESPONSE_TIMEOUT_US {
                    return Err(Nano3TranscriptError::ResponseTooLate {
                        phase: ExchangePhase::Poll,
                        attempt: attempts,
                        elapsed_us,
                        maximum_us: POLL_RESPONSE_TIMEOUT_US,
                    });
                }
                let frame = decode_rx_at(next, cursor)?;
                cursor += 1;
                require_consumed(window.events, cursor)?;
                let next_stock_action = if frame.packet_type == RxType::SummaryStatus {
                    Some(
                        summary_status(&frame)
                            .map_err(|source| Nano3TranscriptError::Envelope {
                                event_index: cursor - 1,
                                source,
                            })?
                            .stock_next_poll_action(),
                    )
                } else {
                    None
                };
                return Ok(ValidatedPollCapture {
                    selector,
                    attempts,
                    outcome: PollCaptureOutcome::Response {
                        packet_type: frame.packet_type,
                        next_stock_action,
                    },
                    digest: transcript_sha256(window),
                });
            }
            CaptureDirection::HostToController => {
                if attempts >= STOCK_POLL_ATTEMPT_LIMIT {
                    return Err(Nano3TranscriptError::TooManyAttempts {
                        phase: ExchangePhase::Poll,
                        maximum: STOCK_POLL_ATTEMPT_LIMIT,
                    });
                }
                if elapsed_us < POLL_RESPONSE_TIMEOUT_US {
                    return Err(Nano3TranscriptError::RetryTooEarly {
                        phase: ExchangePhase::Poll,
                        attempt: attempts + 1,
                        elapsed_us,
                        minimum_us: POLL_RESPONSE_TIMEOUT_US,
                    });
                }
            }
        }
    }
}

pub fn validate_nonce_capture(
    window: CaptureWindow<'_, '_>,
    jobs: &Nano3RecentJobs<Nano3ShareJob>,
    detected_asic_count: u8,
) -> Result<ValidatedNonceCapture, Nano3TranscriptError> {
    validate_capture_clock(window)?;
    if window.events.len() != 1 {
        return Err(Nano3TranscriptError::TrailingEvents {
            event_index: usize::from(!window.events.is_empty()),
            count: window.events.len().saturating_sub(1),
        });
    }
    let event = &window.events[0];
    expect_direction(event, 0, CaptureDirection::ControllerToHost)?;
    let frame = decode_rx_at(event, 0)?;
    if frame.packet_type != RxType::Nonce {
        return Err(Nano3TranscriptError::UnexpectedResponseType {
            phase: ExchangePhase::Nonce,
            event_index: 0,
            expected: RxType::Nonce as u8,
            observed: frame.packet_type as u8,
        });
    }
    let records = nonce_records(&frame).map_err(|source| Nano3TranscriptError::Envelope {
        event_index: 0,
        source,
    })?;
    if records.len() == 0 {
        return Err(Nano3TranscriptError::EmptyNonceBatch);
    }

    let mut nonces = Vec::with_capacity(records.len());
    for (record_index, record) in records.enumerate() {
        let admitted = jobs
            .admit_nonce_candidate(record, detected_asic_count)
            .map_err(|source| Nano3TranscriptError::NonceAdmission {
                record_index,
                source,
            })?;
        nonces.push(verify_share_candidate(admitted).map_err(|source| {
            Nano3TranscriptError::ShareValidation {
                record_index,
                source,
            }
        })?);
    }

    Ok(ValidatedNonceCapture {
        nonces,
        digest: transcript_sha256(window),
    })
}

/// Build the sealed immutable share snapshot paired with an expected job trace.
///
/// Keeping this pairing in one helper prevents a capture test from validating
/// TX bytes against one job while later checking nonces against different work.
fn paired_job_trace_and_snapshot(
    previous_identity: crate::nano3_uart_tx::JobIdentityCache,
    input: StockJobTraceInput<'_>,
) -> Result<(StockJobTrace, Nano3ShareJob), Nano3TxError> {
    let capability = offline_validation_capability();
    let trace = crate::nano3_uart_tx::stock_job_trace(&capability, previous_identity, input)?;
    let snapshot = share_job_snapshot(&capability, input)?;
    Ok((trace, snapshot))
}

fn offline_validation_capability() -> Nano3TxResearchCapability {
    Nano3TxResearchCapability::for_offline_transcript_validation()
}

#[derive(Debug)]
struct OwnedCaptureEvent {
    elapsed_us: u64,
    direction: CaptureDirection,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StrictCapturedFrameError {
    UnexpectedByte {
        frame_offset: usize,
        expected: u8,
        observed: u8,
    },
    Envelope(Nano3UartError),
}

#[derive(Debug, Clone)]
struct StrictCapturedFrameDecoder {
    buffer: [u8; MAX_FRAME_LEN],
    buffered: usize,
    expected: Option<usize>,
}

impl StrictCapturedFrameDecoder {
    const fn new() -> Self {
        Self {
            buffer: [0; MAX_FRAME_LEN],
            buffered: 0,
            expected: None,
        }
    }

    fn push_byte(&mut self, byte: u8) -> Result<Option<Vec<u8>>, StrictCapturedFrameError> {
        if self.buffered < MAGIC.len() {
            let expected = MAGIC[self.buffered];
            if byte != expected {
                return Err(StrictCapturedFrameError::UnexpectedByte {
                    frame_offset: self.buffered,
                    expected,
                    observed: byte,
                });
            }
        }

        debug_assert!(self.buffered < MAX_FRAME_LEN);
        self.buffer[self.buffered] = byte;
        self.buffered += 1;

        if self.buffered == HEADER_LEN {
            let payload_len = u16::from_le_bytes([self.buffer[10], self.buffer[11]]) as usize;
            if payload_len > MAX_PAYLOAD_LEN {
                return Err(StrictCapturedFrameError::Envelope(
                    Nano3UartError::PayloadTooLong(payload_len),
                ));
            }
            self.expected = Some(HEADER_LEN + payload_len);
        }
        if self.expected != Some(self.buffered) {
            return Ok(None);
        }

        decode_native_uart_envelope(&self.buffer[..self.buffered])
            .map_err(StrictCapturedFrameError::Envelope)?;
        let bytes = self.buffer[..self.buffered].to_vec();
        self.buffered = 0;
        self.expected = None;
        Ok(Some(bytes))
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("caller checked fixed-width capture field"),
    )
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("caller checked fixed-width capture field"),
    )
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("caller checked fixed-width capture field"),
    )
}

fn validate_capture_clock(window: CaptureWindow<'_, '_>) -> Result<(), Nano3TranscriptError> {
    let Some(first) = window.events.first() else {
        return Err(Nano3TranscriptError::EmptyCapture);
    };
    let mut previous = first.elapsed_us;
    for (event_index, event) in window.events.iter().enumerate().skip(1) {
        if event.elapsed_us < previous {
            return Err(Nano3TranscriptError::NonMonotonicTime {
                event_index,
                previous_us: previous,
                observed_us: event.elapsed_us,
            });
        }
        previous = event.elapsed_us;
    }
    if window.ended_us < previous {
        return Err(Nano3TranscriptError::EndBeforeLastEvent {
            ended_us: window.ended_us,
            last_event_us: previous,
        });
    }
    Ok(())
}

fn validate_retry_exchange<'bytes>(
    events: &[CaptureEvent<'bytes>],
    mut cursor: usize,
    expected_tx: &Nano3TxFrame,
    expected_rx: RxType,
    phase: ExchangePhase,
    maximum_attempts: u8,
    response_timeout_us: u64,
) -> Result<(usize, RxFrame<'bytes>, u8), Nano3TranscriptError> {
    let mut attempts = 0u8;
    loop {
        expect_exact_tx(events, cursor, expected_tx)?;
        attempts += 1;
        let sent_at = events[cursor].elapsed_us;
        cursor += 1;
        let next = events
            .get(cursor)
            .ok_or(Nano3TranscriptError::IncompleteExchange { phase, attempts })?;
        let elapsed_us = next.elapsed_us - sent_at;
        match next.direction {
            CaptureDirection::ControllerToHost => {
                if elapsed_us > response_timeout_us {
                    return Err(Nano3TranscriptError::ResponseTooLate {
                        phase,
                        attempt: attempts,
                        elapsed_us,
                        maximum_us: response_timeout_us,
                    });
                }
                let frame = decode_rx_at(next, cursor)?;
                if frame.packet_type != expected_rx {
                    return Err(Nano3TranscriptError::UnexpectedResponseType {
                        phase,
                        event_index: cursor,
                        expected: expected_rx as u8,
                        observed: frame.packet_type as u8,
                    });
                }
                return Ok((cursor + 1, frame, attempts));
            }
            CaptureDirection::HostToController => {
                if attempts >= maximum_attempts {
                    return Err(Nano3TranscriptError::TooManyAttempts {
                        phase,
                        maximum: maximum_attempts,
                    });
                }
                if elapsed_us < response_timeout_us {
                    return Err(Nano3TranscriptError::RetryTooEarly {
                        phase,
                        attempt: attempts + 1,
                        elapsed_us,
                        minimum_us: response_timeout_us,
                    });
                }
            }
        }
    }
}

fn expect_exact_tx(
    events: &[CaptureEvent<'_>],
    event_index: usize,
    expected: &Nano3TxFrame,
) -> Result<(), Nano3TranscriptError> {
    let event = events
        .get(event_index)
        .ok_or(Nano3TranscriptError::MissingEvent {
            event_index,
            expected: "host TX frame",
        })?;
    expect_direction(event, event_index, CaptureDirection::HostToController)?;
    let observed = decode_envelope_at(event, event_index)?;
    if event.bytes != expected.as_bytes() {
        return Err(Nano3TranscriptError::TxFrameMismatch {
            event_index,
            expected_type: expected.packet_type(),
            observed_type: observed.packet_type,
        });
    }
    Ok(())
}

fn expect_direction(
    event: &CaptureEvent<'_>,
    event_index: usize,
    expected: CaptureDirection,
) -> Result<(), Nano3TranscriptError> {
    if event.direction != expected {
        return Err(Nano3TranscriptError::UnexpectedDirection {
            event_index,
            expected,
            observed: event.direction,
        });
    }
    Ok(())
}

fn decode_envelope_at<'bytes>(
    event: &CaptureEvent<'bytes>,
    event_index: usize,
) -> Result<crate::nano3_uart::NativeUartEnvelope<'bytes>, Nano3TranscriptError> {
    decode_native_uart_envelope(event.bytes).map_err(|source| Nano3TranscriptError::Envelope {
        event_index,
        source,
    })
}

fn decode_rx_at<'bytes>(
    event: &CaptureEvent<'bytes>,
    event_index: usize,
) -> Result<RxFrame<'bytes>, Nano3TranscriptError> {
    decode_rx_frame(event.bytes).map_err(|source| Nano3TranscriptError::Envelope {
        event_index,
        source,
    })
}

fn decode_poll_selector(
    bytes: &[u8],
    event_index: usize,
) -> Result<ObservedPollSelector, Nano3TranscriptError> {
    let envelope =
        decode_native_uart_envelope(bytes).map_err(|source| Nano3TranscriptError::Envelope {
            event_index,
            source,
        })?;
    if envelope.packet_type != TYPE_POLL
        || envelope.option != 0
        || envelope.index != 0
        || envelope.count != 1
        || envelope.payload.len() != 4
    {
        return Err(Nano3TranscriptError::UnsupportedPollHeader {
            event_index,
            packet_type: envelope.packet_type,
            option: envelope.option,
            index: envelope.index,
            count: envelope.count,
            payload_len: envelope.payload.len(),
        });
    }
    let selector: [u8; 4] = envelope
        .payload
        .try_into()
        .expect("checked poll payload length");
    match selector {
        [0, 0, 0, 0] => Ok(ObservedPollSelector::ReadOnly),
        [0, 0, 0, 1] => Ok(ObservedPollSelector::StatefulReset),
        other => Err(Nano3TranscriptError::UnsupportedPollSelector {
            event_index,
            selector: other,
        }),
    }
}

fn require_consumed(
    events: &[CaptureEvent<'_>],
    cursor: usize,
) -> Result<(), Nano3TranscriptError> {
    if cursor != events.len() {
        return Err(Nano3TranscriptError::TrailingEvents {
            event_index: cursor,
            count: events.len() - cursor,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nano3_uart::{crc16_xmodem, NonceRecord, HEADER_LEN, MAGIC};
    use crate::nano3_uart_rx::{Nano3JobIdentity, NANO3_ASIC_COUNT};
    use crate::nano3_uart_tx::{
        JobIdentityCache, JobParameters, StratumHeaderTemplate, VersionRollingWords,
        MERKLE_BRANCH_LEN,
    };

    fn capability() -> Nano3TxResearchCapability {
        Nano3TxResearchCapability::for_unit_tests()
    }

    fn frame_fixture(packet_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![MAGIC[0], MAGIC[1], 0, 0, packet_type, 0, 0, 0, 1, 0];
        bytes.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        bytes.extend_from_slice(payload);
        let crc = crc16_xmodem(&bytes[4..]);
        bytes[2..4].copy_from_slice(&crc.to_le_bytes());
        bytes
    }

    fn complete_detect_ack(maximum: u8) -> Vec<u8> {
        let mut payload = vec![0xa5; 69];
        payload[4..20].copy_from_slice(&core::array::from_fn::<_, 16, _>(|index| index as u8));
        payload.extend_from_slice(b"model\0firmware\0");
        payload.push(maximum);
        frame_fixture(RxType::DetectAck as u8, &payload)
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                    .expect("valid hex")
            })
            .collect()
    }

    fn genesis_coinbase() -> Vec<u8> {
        let mut script_sig = vec![0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x45];
        script_sig.extend_from_slice(
            b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
        );
        let public_key = decode_hex(concat!(
            "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61de",
            "b649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
        ));
        let mut output_script = vec![0x41];
        output_script.extend_from_slice(&public_key);
        output_script.push(0xac);

        let mut transaction = Vec::new();
        transaction.extend_from_slice(&1u32.to_le_bytes());
        transaction.push(1);
        transaction.extend_from_slice(&[0; 32]);
        transaction.extend_from_slice(&u32::MAX.to_le_bytes());
        transaction.push(script_sig.len() as u8);
        transaction.extend_from_slice(&script_sig);
        transaction.extend_from_slice(&u32::MAX.to_le_bytes());
        transaction.push(1);
        transaction.extend_from_slice(&5_000_000_000u64.to_le_bytes());
        transaction.push(output_script.len() as u8);
        transaction.extend_from_slice(&output_script);
        transaction.extend_from_slice(&0u32.to_le_bytes());
        transaction
    }

    fn genesis_trace_and_jobs() -> (
        StockJobTrace,
        Nano3RecentJobs<Nano3ShareJob>,
        Nano3JobIdentity,
    ) {
        let coinbase = genesis_coinbase();
        let header_template = StratumHeaderTemplate::from_wire_fields(
            1u32.to_be_bytes(),
            [0; 32],
            0x495f_ab29u32.to_be_bytes(),
            0x1d00_ffffu32.to_be_bytes(),
        );
        let input = StockJobTraceInput {
            parameters: JobParameters {
                coinbase_len: coinbase.len() as u32,
                nonce2_offset: 5,
                nonce2_size: 4,
                merkle_branch_count: 0,
                device_index: 0,
                total_devices: 1,
                restart: true,
            },
            versions: VersionRollingWords {
                micro_job_0: 1,
                micro_job_2: 2,
                micro_job_4: 4,
                micro_job_8: 8,
            },
            pool_difficulty: 1.0,
            job_id: "genesis",
            pool_index: 0,
            coinbase: &coinbase,
            merkle_branches: &[],
            header_template: &header_template,
        };
        let (trace, snapshot) =
            paired_job_trace_and_snapshot(JobIdentityCache::default(), input).unwrap();
        let mut jobs = Nano3RecentJobs::new();
        let identity = jobs.remember("genesis", 0, snapshot).unwrap();
        (trace, jobs, identity)
    }

    fn genesis_nonce(identity: Nano3JobIdentity) -> NonceRecord {
        NonceRecord {
            job_id_crc: identity.job_id_crc,
            pool_index: identity.pool_index,
            nonce2: 0,
            nonce: 0x1dac_2b7c,
            asic_id: 0,
            miner_id: 0,
            ntime_offset: 0,
            mid_id: 0,
            valid_marker: 1,
        }
    }

    fn nonce_frame(record: NonceRecord) -> Vec<u8> {
        let mut payload = [0u8; 16];
        payload[..2].copy_from_slice(&record.job_id_crc.to_be_bytes());
        payload[2..4].copy_from_slice(&record.pool_index.to_le_bytes());
        payload[4..8].copy_from_slice(&record.nonce2.to_le_bytes());
        payload[8..12].copy_from_slice(&record.nonce.to_be_bytes());
        payload[12] = record.asic_id;
        payload[13] = record.miner_id;
        payload[14] = record.ntime_offset;
        payload[15] = record.mid_id | (record.valid_marker << 4);
        frame_fixture(RxType::Nonce as u8, &payload)
    }

    fn artifact_fixture() -> Vec<u8> {
        let frame = frame_fixture(RxType::SyncAck as u8, &[]);
        let events = [CaptureEvent {
            elapsed_us: 7,
            direction: CaptureDirection::ControllerToHost,
            bytes: &frame,
        }];
        encode_capture_artifact(CaptureWindow::new(&events, 9)).unwrap()
    }

    #[test]
    fn generic_envelope_decoder_accepts_tx_without_broadening_rx_allowlist() {
        let poll = read_only_poll(&capability());
        let envelope = decode_native_uart_envelope(poll.as_bytes()).unwrap();
        assert_eq!(envelope.packet_type, TYPE_POLL);
        assert_eq!(envelope.payload, [0; 4]);
        assert_eq!(
            decode_rx_frame(poll.as_bytes()),
            Err(Nano3UartError::UnsupportedRxType(TYPE_POLL))
        );
    }

    #[test]
    fn init_capture_validates_retries_timing_identity_and_post_sync_order() {
        let capability = capability();
        let detect = detect_request(&capability);
        let detect_ack = complete_detect_ack(4);
        let detect_frame = decode_rx_frame(&detect_ack).unwrap();
        let contract = DetectAckContract::try_from_detect_ack(&detect_frame).unwrap();
        let sync = sync_request(&capability, contract.sync_identity());
        let sync_ack = frame_fixture(RxType::SyncAck as u8, &[]);
        let sync_frame = decode_rx_frame(&sync_ack).unwrap();
        let post = stock_post_sync_init_trace(&capability, contract, &sync_frame, 2).unwrap();
        let events = [
            CaptureEvent {
                elapsed_us: 0,
                direction: CaptureDirection::HostToController,
                bytes: detect.as_bytes(),
            },
            CaptureEvent {
                elapsed_us: INIT_RESPONSE_TIMEOUT_US,
                direction: CaptureDirection::HostToController,
                bytes: detect.as_bytes(),
            },
            CaptureEvent {
                elapsed_us: INIT_RESPONSE_TIMEOUT_US + 50,
                direction: CaptureDirection::ControllerToHost,
                bytes: &detect_ack,
            },
            CaptureEvent {
                elapsed_us: INIT_RESPONSE_TIMEOUT_US + 100,
                direction: CaptureDirection::HostToController,
                bytes: sync.as_bytes(),
            },
            CaptureEvent {
                elapsed_us: INIT_RESPONSE_TIMEOUT_US + 150,
                direction: CaptureDirection::ControllerToHost,
                bytes: &sync_ack,
            },
            CaptureEvent {
                elapsed_us: INIT_RESPONSE_TIMEOUT_US + 200,
                direction: CaptureDirection::HostToController,
                bytes: post[0].as_bytes(),
            },
            CaptureEvent {
                elapsed_us: INIT_RESPONSE_TIMEOUT_US + 250,
                direction: CaptureDirection::HostToController,
                bytes: post[1].as_bytes(),
            },
        ];
        let window = CaptureWindow::new(&events, INIT_RESPONSE_TIMEOUT_US + 300);
        let report = validate_init_capture(window, 2).unwrap();
        assert_eq!(report.detect_attempts(), 2);
        assert_eq!(report.sync_attempts(), 1);
        assert_eq!(report.detected_work_level_maximum(), 4);
        assert_eq!(report.selected_work_level(), 2);
        assert_eq!(report.digest(), &transcript_sha256(window));

        let mut wrong_post_sync_order = events;
        let first_post_sync = wrong_post_sync_order[5].bytes;
        wrong_post_sync_order[5].bytes = wrong_post_sync_order[6].bytes;
        wrong_post_sync_order[6].bytes = first_post_sync;
        assert!(matches!(
            validate_init_capture(
                CaptureWindow::new(&wrong_post_sync_order, INIT_RESPONSE_TIMEOUT_US + 300),
                2,
            ),
            Err(Nano3TranscriptError::TxFrameMismatch { event_index: 5, .. })
        ));
    }

    #[test]
    fn init_capture_rejects_early_retry() {
        let capability = capability();
        let detect = detect_request(&capability);
        let events = [
            CaptureEvent {
                elapsed_us: 0,
                direction: CaptureDirection::HostToController,
                bytes: detect.as_bytes(),
            },
            CaptureEvent {
                elapsed_us: INIT_RESPONSE_TIMEOUT_US - 1,
                direction: CaptureDirection::HostToController,
                bytes: detect.as_bytes(),
            },
        ];
        assert_eq!(
            validate_init_capture(CaptureWindow::new(&events, INIT_RESPONSE_TIMEOUT_US), 1),
            Err(Nano3TranscriptError::RetryTooEarly {
                phase: ExchangePhase::Detect,
                attempt: 2,
                elapsed_us: INIT_RESPONSE_TIMEOUT_US - 1,
                minimum_us: INIT_RESPONSE_TIMEOUT_US,
            })
        );
    }

    #[test]
    fn job_capture_requires_every_exact_frame_in_exact_order() {
        let coinbase = [0x5au8; 64];
        let header_template =
            StratumHeaderTemplate::from_wire_fields([0; 4], [0; 32], [0; 4], [0; 4]);
        let input = StockJobTraceInput {
            parameters: JobParameters {
                coinbase_len: coinbase.len() as u32,
                nonce2_offset: 4,
                nonce2_size: 4,
                merkle_branch_count: 0,
                device_index: 0,
                total_devices: 1,
                restart: false,
            },
            versions: VersionRollingWords {
                micro_job_0: 0,
                micro_job_2: 2,
                micro_job_4: 4,
                micro_job_8: 8,
            },
            pool_difficulty: 1.0,
            job_id: "capture",
            pool_index: 0,
            coinbase: &coinbase,
            merkle_branches: &[],
            header_template: &header_template,
        };
        let previous_identity = JobIdentityCache::default();
        let (trace, expected_share_job) =
            paired_job_trace_and_snapshot(previous_identity, input).unwrap();
        let events: Vec<_> = trace
            .frames()
            .iter()
            .enumerate()
            .map(|(index, frame)| CaptureEvent {
                elapsed_us: index as u64,
                direction: CaptureDirection::HostToController,
                bytes: frame.as_bytes(),
            })
            .collect();
        let window = CaptureWindow::new(&events, events.len() as u64);
        let report = validate_job_capture(window, previous_identity, input).unwrap();
        assert_eq!(report.frame_count(), trace.frames().len());
        assert!(report.emitted_identity());
        assert_eq!(report.next_identity_cache(), trace.next_identity_cache());
        assert_eq!(report.share_job(), &expected_share_job);

        let truncated = &events[..events.len() - 1];
        assert_eq!(
            validate_job_capture(
                CaptureWindow::new(truncated, truncated.len() as u64),
                previous_identity,
                input,
            ),
            Err(Nano3TranscriptError::JobFrameCountMismatch {
                expected: trace.frames().len(),
                observed: truncated.len(),
            })
        );

        let mut reordered = events.clone();
        let first_bytes = reordered[0].bytes;
        reordered[0].bytes = reordered[1].bytes;
        reordered[1].bytes = first_bytes;
        assert!(matches!(
            validate_job_capture(
                CaptureWindow::new(&reordered, reordered.len() as u64),
                previous_identity,
                input,
            ),
            Err(Nano3TranscriptError::TxFrameMismatch { event_index: 0, .. })
        ));
    }

    #[test]
    fn poll_capture_classifies_read_only_response_and_never_authorizes_tx() {
        let capability = capability();
        let poll = read_only_poll(&capability);
        let mut status_payload = [0u8; 52];
        status_payload[0] = 4;
        let response = frame_fixture(RxType::SummaryStatus as u8, &status_payload);
        let events = [
            CaptureEvent {
                elapsed_us: 10,
                direction: CaptureDirection::HostToController,
                bytes: poll.as_bytes(),
            },
            CaptureEvent {
                elapsed_us: 20,
                direction: CaptureDirection::ControllerToHost,
                bytes: &response,
            },
        ];
        let report = validate_poll_capture(CaptureWindow::new(&events, 20)).unwrap();
        assert_eq!(report.selector(), ObservedPollSelector::ReadOnly);
        assert_eq!(report.attempts(), 1);
        assert_eq!(
            report.outcome(),
            PollCaptureOutcome::Response {
                packet_type: RxType::SummaryStatus,
                next_stock_action: Some(StockNextPollAction::StatefulResetSelector),
            }
        );
        assert!(!report.authorizes_transmit());
    }

    #[test]
    fn poll_capture_can_observe_but_not_authorize_stateful_selector() {
        let stateful = frame_fixture(TYPE_POLL, &[0, 0, 0, 1]);
        let response = frame_fixture(RxType::Status52 as u8, &[]);
        let events = [
            CaptureEvent {
                elapsed_us: 0,
                direction: CaptureDirection::HostToController,
                bytes: &stateful,
            },
            CaptureEvent {
                elapsed_us: 1,
                direction: CaptureDirection::ControllerToHost,
                bytes: &response,
            },
        ];
        let report = validate_poll_capture(CaptureWindow::new(&events, 1)).unwrap();
        assert_eq!(report.selector(), ObservedPollSelector::StatefulReset);
        assert!(!report.authorizes_transmit());
        assert!(matches!(
            report.outcome(),
            PollCaptureOutcome::Response {
                packet_type: RxType::Status52,
                next_stock_action: None,
            }
        ));
    }

    #[test]
    fn poll_capture_requires_full_timeout_to_prove_exhaustion() {
        let capability = capability();
        let poll = read_only_poll(&capability);
        let events: Vec<_> = (0..STOCK_POLL_ATTEMPT_LIMIT)
            .map(|attempt| CaptureEvent {
                elapsed_us: u64::from(attempt) * POLL_RESPONSE_TIMEOUT_US,
                direction: CaptureDirection::HostToController,
                bytes: poll.as_bytes(),
            })
            .collect();
        let last = events.last().unwrap().elapsed_us;
        assert_eq!(
            validate_poll_capture(CaptureWindow::new(
                &events,
                last + POLL_RESPONSE_TIMEOUT_US - 1,
            )),
            Err(Nano3TranscriptError::CaptureEndedBeforeTimeout {
                phase: ExchangePhase::Poll,
                observed_us: POLL_RESPONSE_TIMEOUT_US - 1,
                minimum_us: POLL_RESPONSE_TIMEOUT_US,
            })
        );
        let report =
            validate_poll_capture(CaptureWindow::new(&events, last + POLL_RESPONSE_TIMEOUT_US))
                .unwrap();
        assert_eq!(report.attempts(), STOCK_POLL_ATTEMPT_LIMIT);
        assert_eq!(
            report.outcome(),
            PollCaptureOutcome::ExhaustedWithoutResponse
        );
    }

    #[test]
    fn poll_capture_rejects_unproven_selector() {
        let unsupported = frame_fixture(TYPE_POLL, &[0, 0, 0, 2]);
        let events = [CaptureEvent {
            elapsed_us: 0,
            direction: CaptureDirection::HostToController,
            bytes: &unsupported,
        }];
        assert_eq!(
            validate_poll_capture(CaptureWindow::new(&events, POLL_RESPONSE_TIMEOUT_US)),
            Err(Nano3TranscriptError::UnsupportedPollSelector {
                event_index: 0,
                selector: [0, 0, 0, 2],
            })
        );
    }

    #[test]
    fn poll_capture_rejects_a_changed_retry_request() {
        let capability = capability();
        let read_only = read_only_poll(&capability);
        let stateful = frame_fixture(TYPE_POLL, &[0, 0, 0, 1]);
        let events = [
            CaptureEvent {
                elapsed_us: 0,
                direction: CaptureDirection::HostToController,
                bytes: read_only.as_bytes(),
            },
            CaptureEvent {
                elapsed_us: POLL_RESPONSE_TIMEOUT_US,
                direction: CaptureDirection::HostToController,
                bytes: &stateful,
            },
        ];
        assert_eq!(
            validate_poll_capture(CaptureWindow::new(&events, POLL_RESPONSE_TIMEOUT_US)),
            Err(Nano3TranscriptError::PollRetryChanged { event_index: 1 })
        );
    }

    #[test]
    fn nonce_capture_replays_genesis_against_the_exact_retained_job() {
        let (_, jobs, identity) = genesis_trace_and_jobs();
        let nonce = nonce_frame(genesis_nonce(identity));
        let events = [CaptureEvent {
            elapsed_us: 1,
            direction: CaptureDirection::ControllerToHost,
            bytes: &nonce,
        }];
        let report =
            validate_nonce_capture(CaptureWindow::new(&events, 1), &jobs, NANO3_ASIC_COUNT)
                .unwrap();
        assert_eq!(report.nonces().len(), 1);
        assert_eq!(
            report.nonces()[0].hash(),
            decode_hex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")
                .as_slice()
        );
    }

    #[test]
    fn nonce_capture_rejects_empty_and_cryptographically_invalid_batches() {
        let (_, jobs, identity) = genesis_trace_and_jobs();
        let empty = frame_fixture(RxType::Nonce as u8, &[]);
        let empty_events = [CaptureEvent {
            elapsed_us: 0,
            direction: CaptureDirection::ControllerToHost,
            bytes: &empty,
        }];
        assert_eq!(
            validate_nonce_capture(
                CaptureWindow::new(&empty_events, 0),
                &jobs,
                NANO3_ASIC_COUNT
            ),
            Err(Nano3TranscriptError::EmptyNonceBatch)
        );

        let mut invalid_record = genesis_nonce(identity);
        invalid_record.nonce = invalid_record.nonce.wrapping_add(1);
        let invalid = nonce_frame(invalid_record);
        let invalid_events = [CaptureEvent {
            elapsed_us: 1,
            direction: CaptureDirection::ControllerToHost,
            bytes: &invalid,
        }];
        assert_eq!(
            validate_nonce_capture(
                CaptureWindow::new(&invalid_events, 1),
                &jobs,
                NANO3_ASIC_COUNT
            ),
            Err(Nano3TranscriptError::ShareValidation {
                record_index: 0,
                source: Nano3ShareError::DoesNotMeetStockDifficultyOne,
            })
        );
    }

    #[test]
    fn capture_digest_is_domain_separated_and_binds_end_time() {
        let frame = frame_fixture(RxType::SyncAck as u8, &[]);
        assert_eq!(frame.len(), HEADER_LEN);
        let events = [CaptureEvent {
            elapsed_us: 7,
            direction: CaptureDirection::ControllerToHost,
            bytes: &frame,
        }];
        let first = transcript_sha256(CaptureWindow::new(&events, 9));
        let second = transcript_sha256(CaptureWindow::new(&events, 10));
        assert_ne!(first, second);
        assert_eq!(
            first.as_slice(),
            decode_hex("43049d194a6f6fbe0e0ff31f2941c73b44d304a15b75d4f90078f8475946a506")
                .as_slice()
        );
    }

    #[test]
    fn portable_artifact_round_trips_without_copying_or_authorizing_frames() {
        let sync = frame_fixture(RxType::SyncAck as u8, &[]);
        let status = frame_fixture(RxType::Status52 as u8, &[0xaa, 0x55]);
        let events = [
            CaptureEvent {
                elapsed_us: 7,
                direction: CaptureDirection::ControllerToHost,
                bytes: &sync,
            },
            CaptureEvent {
                elapsed_us: 11,
                direction: CaptureDirection::ControllerToHost,
                bytes: &status,
            },
        ];
        let window = CaptureWindow::new(&events, 12);
        let encoded = encode_capture_artifact(window).unwrap();
        let decoded = decode_capture_artifact(&encoded).unwrap();
        assert_eq!(decoded.events(), events);
        assert_eq!(decoded.ended_us(), 12);
        assert_eq!(decoded.digest(), &transcript_sha256(window));
        assert_eq!(encode_capture_artifact(decoded.window()).unwrap(), encoded);

        let first_offset = CAPTURE_ARTIFACT_HEADER_LEN + CAPTURE_ARTIFACT_EVENT_HEADER_LEN;
        assert_eq!(
            decoded.events()[0].bytes.as_ptr(),
            encoded[first_offset..].as_ptr()
        );
    }

    #[test]
    fn portable_artifact_matches_independent_version_one_golden_bytes() {
        let encoded = artifact_fixture();
        assert_eq!(encoded.len(), 92);
        assert_eq!(
            encoded,
            decode_hex(concat!(
                "44434e3343415000", // DCN3CAP\0
                "01004000",         // version 1, 64-byte header
                "01000000",         // one event
                "0900000000000000", // capture ended_us
                "43049d194a6f6fbe0e0ff31f2941c73b",
                "44d304a15b75d4f90078f8475946a506", // logical transcript digest
                "0000000000000000",                 // header reserved
                "0700000000000000",                 // event elapsed_us
                "0100",                             // controller-to-host, zero flags
                "0c00",                             // 12-byte frame
                "00000000",                         // event reserved
                "434e75831300000001000000",         // exact empty type-0x13 frame
            ))
        );
    }

    #[test]
    fn artifact_encoder_refuses_empty_invalid_and_unbounded_inputs() {
        assert_eq!(
            encode_capture_artifact(CaptureWindow::new(&[], 0)),
            Err(Nano3CaptureArtifactError::Transcript {
                source: Nano3TranscriptError::EmptyCapture,
            })
        );

        let invalid_frame = [0u8; HEADER_LEN];
        let invalid_events = [CaptureEvent {
            elapsed_us: 0,
            direction: CaptureDirection::HostToController,
            bytes: &invalid_frame,
        }];
        assert!(matches!(
            encode_capture_artifact(CaptureWindow::new(&invalid_events, 0)),
            Err(Nano3CaptureArtifactError::Envelope {
                event_index: 0,
                source: Nano3UartError::BadMagic(0, 0),
            })
        ));

        let frame = frame_fixture(RxType::SyncAck as u8, &[]);
        let too_many = vec![
            CaptureEvent {
                elapsed_us: 0,
                direction: CaptureDirection::ControllerToHost,
                bytes: &frame,
            };
            CAPTURE_ARTIFACT_MAX_EVENTS + 1
        ];
        assert_eq!(
            encode_capture_artifact(CaptureWindow::new(&too_many, 0)),
            Err(Nano3CaptureArtifactError::TooManyEvents {
                observed: CAPTURE_ARTIFACT_MAX_EVENTS + 1,
                maximum: CAPTURE_ARTIFACT_MAX_EVENTS,
            })
        );
    }

    #[test]
    fn artifact_extraction_is_contiguous_conservative_and_canonical() {
        let first = frame_fixture(RxType::DetectAck as u8, &[0x01]);
        let second = frame_fixture(RxType::SyncAck as u8, &[0x02]);
        let third = frame_fixture(RxType::Status52 as u8, &[0x03]);
        let events = [
            CaptureEvent {
                elapsed_us: 10,
                direction: CaptureDirection::ControllerToHost,
                bytes: &first,
            },
            CaptureEvent {
                elapsed_us: 30,
                direction: CaptureDirection::ControllerToHost,
                bytes: &second,
            },
            CaptureEvent {
                elapsed_us: 50,
                direction: CaptureDirection::ControllerToHost,
                bytes: &third,
            },
        ];
        let window = CaptureWindow::new(&events, 70);

        let prefix_bytes = extract_capture_artifact(window, 0, 2).unwrap();
        let prefix = decode_capture_artifact(&prefix_bytes).unwrap();
        assert_eq!(prefix.events(), &events[..2]);
        assert_eq!(prefix.ended_us(), 30);
        assert_eq!(
            encode_capture_artifact(prefix.window()).unwrap(),
            prefix_bytes
        );

        let suffix = extract_capture_artifact(window, 2, 1).unwrap();
        let suffix = decode_capture_artifact(&suffix).unwrap();
        assert_eq!(suffix.events(), &events[2..]);
        assert_eq!(suffix.ended_us(), 70);
    }

    #[test]
    fn artifact_extraction_rejects_empty_out_of_range_and_ambiguous_boundaries() {
        let frame = frame_fixture(RxType::SyncAck as u8, &[]);
        let events = [
            CaptureEvent {
                elapsed_us: 7,
                direction: CaptureDirection::ControllerToHost,
                bytes: &frame,
            },
            CaptureEvent {
                elapsed_us: 7,
                direction: CaptureDirection::ControllerToHost,
                bytes: &frame,
            },
        ];
        let window = CaptureWindow::new(&events, 9);

        assert_eq!(
            extract_capture_artifact(window, 0, 0),
            Err(Nano3CaptureArtifactError::EmptySelection)
        );
        assert_eq!(
            extract_capture_artifact(window, 2, 1),
            Err(Nano3CaptureArtifactError::SelectionStartOutOfRange {
                first_event: 2,
                available: 2,
            })
        );
        assert_eq!(
            extract_capture_artifact(window, 1, 2),
            Err(Nano3CaptureArtifactError::SelectionEndOutOfRange {
                first_event: 1,
                event_count: 2,
                available: 2,
            })
        );
        assert_eq!(
            extract_capture_artifact(window, 0, 1),
            Err(
                Nano3CaptureArtifactError::IndistinguishableSelectionBoundary {
                    last_event: 0,
                    last_event_us: 7,
                    next_event: 1,
                    next_event_us: 7,
                }
            )
        );
    }

    #[test]
    fn artifact_decoder_rejects_noncanonical_headers_and_record_metadata() {
        let canonical = artifact_fixture();

        let mut bad_magic = canonical.clone();
        bad_magic[0] ^= 1;
        assert!(matches!(
            decode_capture_artifact(&bad_magic),
            Err(Nano3CaptureArtifactError::BadMagic(_))
        ));

        let mut bad_version = canonical.clone();
        bad_version[ARTIFACT_VERSION_OFFSET..ARTIFACT_VERSION_OFFSET + 2]
            .copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            decode_capture_artifact(&bad_version),
            Err(Nano3CaptureArtifactError::UnsupportedVersion(2))
        );

        let mut bad_header_len = canonical.clone();
        bad_header_len[ARTIFACT_HEADER_LEN_OFFSET..ARTIFACT_HEADER_LEN_OFFSET + 2]
            .copy_from_slice(&63u16.to_le_bytes());
        assert_eq!(
            decode_capture_artifact(&bad_header_len),
            Err(Nano3CaptureArtifactError::NonCanonicalHeaderLength {
                observed: 63,
                expected: CAPTURE_ARTIFACT_HEADER_LEN,
            })
        );

        let mut too_many_events = canonical.clone();
        too_many_events[ARTIFACT_EVENT_COUNT_OFFSET..ARTIFACT_EVENT_COUNT_OFFSET + 4]
            .copy_from_slice(&((CAPTURE_ARTIFACT_MAX_EVENTS + 1) as u32).to_le_bytes());
        assert_eq!(
            decode_capture_artifact(&too_many_events),
            Err(Nano3CaptureArtifactError::TooManyEvents {
                observed: CAPTURE_ARTIFACT_MAX_EVENTS + 1,
                maximum: CAPTURE_ARTIFACT_MAX_EVENTS,
            })
        );

        let mut header_reserved = canonical.clone();
        header_reserved[ARTIFACT_HEADER_RESERVED_OFFSET] = 1;
        assert_eq!(
            decode_capture_artifact(&header_reserved),
            Err(Nano3CaptureArtifactError::NonZeroHeaderReserved)
        );

        let event_offset = CAPTURE_ARTIFACT_HEADER_LEN;
        let mut direction = canonical.clone();
        direction[event_offset + 8] = 2;
        assert_eq!(
            decode_capture_artifact(&direction),
            Err(Nano3CaptureArtifactError::InvalidDirection {
                event_index: 0,
                observed: 2,
            })
        );

        let mut flags = canonical.clone();
        flags[event_offset + 9] = 1;
        assert_eq!(
            decode_capture_artifact(&flags),
            Err(Nano3CaptureArtifactError::NonZeroEventFlags { event_index: 0 })
        );

        let mut event_reserved = canonical.clone();
        event_reserved[event_offset + 12] = 1;
        assert_eq!(
            decode_capture_artifact(&event_reserved),
            Err(Nano3CaptureArtifactError::NonZeroEventReserved { event_index: 0 })
        );
    }

    #[test]
    fn artifact_decoder_rejects_bounds_truncation_trailing_bytes_and_digest_drift() {
        assert_eq!(
            decode_capture_artifact(&[0; CAPTURE_ARTIFACT_HEADER_LEN - 1]),
            Err(Nano3CaptureArtifactError::TooShort {
                observed: CAPTURE_ARTIFACT_HEADER_LEN - 1,
                minimum: CAPTURE_ARTIFACT_HEADER_LEN,
            })
        );
        assert_eq!(
            decode_capture_artifact(&vec![0; CAPTURE_ARTIFACT_MAX_LEN + 1]),
            Err(Nano3CaptureArtifactError::TooLong {
                observed: CAPTURE_ARTIFACT_MAX_LEN + 1,
                maximum: CAPTURE_ARTIFACT_MAX_LEN,
            })
        );

        let canonical = artifact_fixture();
        let event_offset = CAPTURE_ARTIFACT_HEADER_LEN;

        let truncated_header = &canonical[..CAPTURE_ARTIFACT_HEADER_LEN + 15];
        assert_eq!(
            decode_capture_artifact(truncated_header),
            Err(Nano3CaptureArtifactError::TruncatedEventHeader {
                event_index: 0,
                remaining: 15,
            })
        );

        let mut truncated_frame = canonical.clone();
        truncated_frame[event_offset + 10..event_offset + 12].copy_from_slice(&13u16.to_le_bytes());
        assert_eq!(
            decode_capture_artifact(&truncated_frame),
            Err(Nano3CaptureArtifactError::TruncatedFrame {
                event_index: 0,
                declared: 13,
                available: 12,
            })
        );

        let mut trailing = canonical.clone();
        trailing.push(0);
        assert_eq!(
            decode_capture_artifact(&trailing),
            Err(Nano3CaptureArtifactError::TrailingBytes(1))
        );

        let mut digest_drift = canonical.clone();
        digest_drift[ARTIFACT_ENDED_US_OFFSET..ARTIFACT_ENDED_US_OFFSET + 8]
            .copy_from_slice(&10u64.to_le_bytes());
        assert!(matches!(
            decode_capture_artifact(&digest_drift),
            Err(Nano3CaptureArtifactError::DigestMismatch { .. })
        ));

        let mut invalid_frame = canonical;
        let frame_offset = event_offset + CAPTURE_ARTIFACT_EVENT_HEADER_LEN;
        invalid_frame[frame_offset + 2] ^= 1;
        assert!(matches!(
            decode_capture_artifact(&invalid_frame),
            Err(Nano3CaptureArtifactError::Envelope {
                event_index: 0,
                source: Nano3UartError::CrcMismatch { .. },
            })
        ));
    }

    #[test]
    fn raw_chunk_assembler_preserves_direction_completion_order_and_timing() {
        let capability = capability();
        let poll = read_only_poll(&capability);
        let response = frame_fixture(RxType::Status52 as u8, &[0xaa]);
        let chunks = [
            CaptureByteChunk {
                elapsed_us: 1,
                direction: CaptureDirection::HostToController,
                bytes: &poll.as_bytes()[..5],
            },
            CaptureByteChunk {
                elapsed_us: 2,
                direction: CaptureDirection::ControllerToHost,
                bytes: &response[..4],
            },
            CaptureByteChunk {
                elapsed_us: 3,
                direction: CaptureDirection::HostToController,
                bytes: &poll.as_bytes()[5..],
            },
            CaptureByteChunk {
                elapsed_us: 4,
                direction: CaptureDirection::ControllerToHost,
                bytes: &response[4..],
            },
        ];
        let artifact = assemble_capture_artifact(&chunks, 5).unwrap();
        let decoded = decode_capture_artifact(&artifact).unwrap();
        assert_eq!(decoded.ended_us(), 5);
        assert_eq!(decoded.events().len(), 2);
        assert_eq!(decoded.events()[0].elapsed_us, 3);
        assert_eq!(
            decoded.events()[0].direction,
            CaptureDirection::HostToController
        );
        assert_eq!(decoded.events()[0].bytes, poll.as_bytes());
        assert_eq!(decoded.events()[1].elapsed_us, 4);
        assert_eq!(
            decoded.events()[1].direction,
            CaptureDirection::ControllerToHost
        );
        assert_eq!(decoded.events()[1].bytes, response);
    }

    #[test]
    fn raw_chunk_assembler_rejects_noise_and_corrupt_frames_without_resync() {
        let leading_noise = [0u8];
        let chunks = [CaptureByteChunk {
            elapsed_us: 0,
            direction: CaptureDirection::HostToController,
            bytes: &leading_noise,
        }];
        assert_eq!(
            assemble_capture_artifact(&chunks, 0),
            Err(Nano3CaptureAssemblyError::UnexpectedFrameByte {
                chunk_index: 0,
                byte_offset: 0,
                direction: CaptureDirection::HostToController,
                frame_offset: 0,
                expected: MAGIC[0],
                observed: 0,
            })
        );

        let bad_second_magic = [MAGIC[0], 0];
        let chunks = [CaptureByteChunk {
            elapsed_us: 0,
            direction: CaptureDirection::ControllerToHost,
            bytes: &bad_second_magic,
        }];
        assert_eq!(
            assemble_capture_artifact(&chunks, 0),
            Err(Nano3CaptureAssemblyError::UnexpectedFrameByte {
                chunk_index: 0,
                byte_offset: 1,
                direction: CaptureDirection::ControllerToHost,
                frame_offset: 1,
                expected: MAGIC[1],
                observed: 0,
            })
        );

        let mut bad_crc = frame_fixture(RxType::SyncAck as u8, &[]);
        bad_crc[2] ^= 1;
        let chunks = [CaptureByteChunk {
            elapsed_us: 0,
            direction: CaptureDirection::ControllerToHost,
            bytes: &bad_crc,
        }];
        assert!(matches!(
            assemble_capture_artifact(&chunks, 0),
            Err(Nano3CaptureAssemblyError::Envelope {
                chunk_index: 0,
                byte_offset: 11,
                direction: CaptureDirection::ControllerToHost,
                source: Nano3UartError::CrcMismatch { .. },
            })
        ));
    }

    #[test]
    fn raw_chunk_assembler_rejects_empty_time_and_size_boundary_drift() {
        assert_eq!(
            assemble_capture_artifact(&[], 0),
            Err(Nano3CaptureAssemblyError::EmptyInput)
        );

        let empty_chunks = [CaptureByteChunk {
            elapsed_us: 0,
            direction: CaptureDirection::HostToController,
            bytes: &[],
        }];
        assert_eq!(
            assemble_capture_artifact(&empty_chunks, 0),
            Err(Nano3CaptureAssemblyError::EmptyChunk { chunk_index: 0 })
        );

        let frame = frame_fixture(RxType::SyncAck as u8, &[]);
        let nonmonotonic = [
            CaptureByteChunk {
                elapsed_us: 2,
                direction: CaptureDirection::ControllerToHost,
                bytes: &frame,
            },
            CaptureByteChunk {
                elapsed_us: 1,
                direction: CaptureDirection::ControllerToHost,
                bytes: &frame,
            },
        ];
        assert_eq!(
            assemble_capture_artifact(&nonmonotonic, 2),
            Err(Nano3CaptureAssemblyError::NonMonotonicChunk {
                chunk_index: 1,
                previous_us: 2,
                observed_us: 1,
            })
        );

        let oversized = vec![0; CAPTURE_ASSEMBLY_MAX_RAW_BYTES + 1];
        let oversized_chunks = [CaptureByteChunk {
            elapsed_us: 0,
            direction: CaptureDirection::HostToController,
            bytes: &oversized,
        }];
        assert_eq!(
            assemble_capture_artifact(&oversized_chunks, 0),
            Err(Nano3CaptureAssemblyError::TooManyRawBytes {
                maximum: CAPTURE_ASSEMBLY_MAX_RAW_BYTES,
            })
        );
    }

    #[test]
    fn raw_chunk_assembler_rejects_incomplete_excess_and_early_end() {
        let frame = frame_fixture(RxType::SyncAck as u8, &[]);
        let partial_chunks = [CaptureByteChunk {
            elapsed_us: 4,
            direction: CaptureDirection::ControllerToHost,
            bytes: &frame[..3],
        }];
        assert_eq!(
            assemble_capture_artifact(&partial_chunks, 4),
            Err(Nano3CaptureAssemblyError::IncompleteFrame {
                direction: CaptureDirection::ControllerToHost,
                buffered: 3,
                expected: None,
            })
        );

        let complete_chunks = [CaptureByteChunk {
            elapsed_us: 4,
            direction: CaptureDirection::ControllerToHost,
            bytes: &frame,
        }];
        assert_eq!(
            assemble_capture_artifact(&complete_chunks, 3),
            Err(Nano3CaptureAssemblyError::EndBeforeLastChunk {
                ended_us: 3,
                last_chunk_us: 4,
            })
        );

        let repeated = frame.repeat(CAPTURE_ARTIFACT_MAX_EVENTS + 1);
        let repeated_chunks = [CaptureByteChunk {
            elapsed_us: 0,
            direction: CaptureDirection::ControllerToHost,
            bytes: &repeated,
        }];
        assert_eq!(
            assemble_capture_artifact(&repeated_chunks, 0),
            Err(Nano3CaptureAssemblyError::TooManyEvents {
                maximum: CAPTURE_ARTIFACT_MAX_EVENTS,
            })
        );
    }

    #[test]
    fn capture_clock_rejects_backward_events_and_early_end() {
        let frame = frame_fixture(RxType::SyncAck as u8, &[]);
        let events = [
            CaptureEvent {
                elapsed_us: 2,
                direction: CaptureDirection::ControllerToHost,
                bytes: &frame,
            },
            CaptureEvent {
                elapsed_us: 1,
                direction: CaptureDirection::ControllerToHost,
                bytes: &frame,
            },
        ];
        assert!(matches!(
            validate_capture_clock(CaptureWindow::new(&events, 2)),
            Err(Nano3TranscriptError::NonMonotonicTime { event_index: 1, .. })
        ));
        let one = &events[..1];
        assert_eq!(
            validate_capture_clock(CaptureWindow::new(one, 1)),
            Err(Nano3TranscriptError::EndBeforeLastEvent {
                ended_us: 1,
                last_event_us: 2,
            })
        );
    }

    #[test]
    fn synthetic_job_still_honors_merkle_count_contract() {
        let coinbase = [0u8; 64];
        let branches = [[0u8; MERKLE_BRANCH_LEN]];
        let header = StratumHeaderTemplate::from_wire_fields([0; 4], [0; 32], [0; 4], [0; 4]);
        let input = StockJobTraceInput {
            parameters: JobParameters {
                coinbase_len: 64,
                nonce2_offset: 4,
                nonce2_size: 4,
                merkle_branch_count: 0,
                device_index: 0,
                total_devices: 1,
                restart: false,
            },
            versions: VersionRollingWords {
                micro_job_0: 0,
                micro_job_2: 0,
                micro_job_4: 0,
                micro_job_8: 0,
            },
            pool_difficulty: 1.0,
            job_id: "bad",
            pool_index: 0,
            coinbase: &coinbase,
            merkle_branches: &branches,
            header_template: &header,
        };
        assert!(matches!(
            paired_job_trace_and_snapshot(JobIdentityCache::default(), input),
            Err(Nano3TxError::MerkleCountMismatch { .. })
        ));
    }
}
