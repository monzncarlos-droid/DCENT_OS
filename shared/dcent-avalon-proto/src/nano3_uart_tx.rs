// SPDX-License-Identifier: GPL-3.0-or-later
//
// Pure, bounded serialization for held-binary-proven portions of the original
// (non-3S) Avalon Nano 3 native UART protocol.
//
// Evidence boundary (stock `btcminer` SHA-256 e6c11630...ca6751):
//   - `detect_modules`             0x0002ad20
//   - `avalonnano_sswork_update`  0x0002a160
//   - `data_toast_send`           0x000b58d0
//   - `crc16`                     0x0014d6a0
//.
//
// There is intentionally no UART/file-descriptor code here.  Producing a
// `Nano3TxFrame` is not permission to transmit it.  The explicit authority
// gate below remains closed, the target profile still reports
// `native_tx_authorized=false`, and the live-qualified init/job contracts
// refuse while safe controller sequencing and acknowledgement behavior remain
// unresolved.  No PLL, frequency, voltage, reset, fan, thermal, or power
// command has an encoder in this module.

use crate::nano3_uart::{crc16_xmodem, RxFrame, RxType, HEADER_LEN, MAGIC, MAX_FRAME_LEN};
use crate::nano3_uart_rx::StructurallyAdmittedNonce;
use sha2::{Digest, Sha256};

/// Exact payload size copied from a detect acknowledgement into sync.
pub const SYNC_IDENTITY_LEN: usize = 16;

/// Offset of the two opaque eight-byte sync values in the detect-ack payload.
pub const SYNC_IDENTITY_DETECT_PAYLOAD_OFFSET: usize = 4;

/// Exact attempt count used independently for detect and sync exchanges.
pub const STOCK_INIT_ATTEMPT_LIMIT: u8 = 5;

/// Exact receive timeout used for each detect and sync attempt.
pub const STOCK_INIT_RESPONSE_TIMEOUT_MS: u32 = 200;

/// Size used by stock for coinbase fragments and the UART payload ceiling.
pub const COINBASE_FRAGMENT_LEN: usize = 128;

/// One merkle branch and one type-0x23 payload.
pub const MERKLE_BRANCH_LEN: usize = 32;

/// Stock's hard ceiling for one Stratum job's merkle branches.
pub const MAX_MERKLE_BRANCH_COUNT: usize = 30;

/// Exact `pool->header_bin` template copied by stock as four 32-byte chunks.
pub const WORK_24_BLOCK_LEN: usize = 128;

/// Type-0x24 always carries exactly four chunks.
pub const WORK_24_CHUNK_COUNT: usize = 4;

/// Stock stores fragment index/count through one-byte values even though the
/// envelope fields are u16.  Refuse rather than wrap beyond this bound.
pub const MAX_FRAGMENT_COUNT: usize = u8::MAX as usize;

/// Stock caps the pool difficulty used for the type-0x25 target at 4096.
pub const STOCK_MAX_TARGET_DIFFICULTY: f64 = 4096.0;

/// Maximum bytes from stock's nonce2-aligned SHA-256 boundary to coinbase end.
///
/// Stock reports this plus one 64-byte SHA-256 block as a maximum modified
/// coinbase size of `0x1840` bytes.
pub const MAX_MODIFIED_COINBASE_TAIL_LEN: u32 = 0x1800;

const DETECT_IDENTITY_END: usize = SYNC_IDENTITY_DETECT_PAYLOAD_OFFSET + SYNC_IDENTITY_LEN;
const DETECT_FIRST_DYNAMIC_FIELD_OFFSET: usize = 69;
const DETECT_MINIMUM_COMPLETE_PAYLOAD_LEN: usize = 72;
const MERKLE_OFFSET: u32 = 36;
const NONCE2_SIZE_THREE_RANGE: u32 = 0x00ff_ffff;
const SHA256_BLOCK_LEN: u32 = 64;
const SHA256_WORK_PADDING: [u8; 48] = sha256_work_padding();

// Exact cgminer `set_target` constants retained in the held binary and
// cross-confirmed against the held Canaan source.
const TRUE_DIFF_ONE: f64 = 26959535291011309493156476344723991336010898738574164086137773096960.0;
const BITS_192: f64 = 6277101735386680763835789423207666416102355444464034512896.0;
const BITS_128: f64 = 340282366920938463463374607431768211456.0;
const BITS_64: f64 = 18446744073709551616.0;

const TYPE_DETECT: u8 = 0x10;
const TYPE_SYNC: u8 = 0x12;
const TYPE_JOB_PARAMETERS: u8 = 0x20;
const TYPE_JOB_IDENTITY: u8 = 0x21;
const TYPE_COINBASE: u8 = 0x22;
const TYPE_MERKLE: u8 = 0x23;
const TYPE_WORK_24: u8 = 0x24;
const TYPE_TARGET: u8 = 0x25;
const TYPE_JOB_FINISH: u8 = 0x26;
const TYPE_VERSION_WORDS: u8 = 0x27;
const TYPE_INIT_FINISH: u8 = 0x31;
const TYPE_READ_ONLY_POLL: u8 = 0x33;
const TYPE_WORK_LEVEL: u8 = 0x41;

/// One fixed-capacity, exact-length native UART frame.
///
/// The backing array prevents an oversized payload from being represented.
/// `as_bytes()` returns only the initialized `12 + payload_len` prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "serializing a frame grants no authority to transmit it"]
pub struct Nano3TxFrame {
    bytes: [u8; MAX_FRAME_LEN],
    len: usize,
}

impl Nano3TxFrame {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        false
    }

    pub const fn packet_type(&self) -> u8 {
        self.bytes[4]
    }
}

/// Opaque sync identity copied byte-for-byte from one validated detect ack.
///
/// The fields stay private because their meanings are not proved.  This module
/// only derives them from the exact payload window of a type-0x11 `RxFrame`;
/// callers must obtain that frame through the CRC-validating RX decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncIdentity([u8; SYNC_IDENTITY_LEN]);

impl SyncIdentity {
    pub fn try_from_detect_ack(frame: &RxFrame<'_>) -> Result<Self, Nano3TxError> {
        if frame.packet_type != RxType::DetectAck {
            return Err(Nano3TxError::UnexpectedDetectResponseType(
                frame.packet_type as u8,
            ));
        }
        if frame.payload.len() < DETECT_IDENTITY_END {
            return Err(Nano3TxError::DetectPayloadTooShort {
                observed: frame.payload.len(),
                required: DETECT_IDENTITY_END,
            });
        }

        let mut identity = [0u8; SYNC_IDENTITY_LEN];
        identity.copy_from_slice(
            &frame.payload[SYNC_IDENTITY_DETECT_PAYLOAD_OFFSET..DETECT_IDENTITY_END],
        );
        Ok(Self(identity))
    }
}

/// Work-level ceiling recovered from one validated type-0x11 detect response.
///
/// Its field is private so a caller cannot substitute an arbitrary maximum for
/// stock's strict requested-versus-detected selection rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectedWorkLevelMaximum(u8);

impl DetectedWorkLevelMaximum {
    pub const fn value(self) -> u8 {
        self.0
    }
}

/// The two detect-response values needed by the proven init frame sequence.
///
/// Stock locates the maximum after two NUL-terminated opaque identification
/// fields beginning at payload offset 69. This parser bounds both searches to
/// the already CRC-validated receive payload and refuses truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectAckContract {
    sync_identity: SyncIdentity,
    work_level_maximum: DetectedWorkLevelMaximum,
}

impl DetectAckContract {
    pub fn try_from_detect_ack(frame: &RxFrame<'_>) -> Result<Self, Nano3TxError> {
        let sync_identity = SyncIdentity::try_from_detect_ack(frame)?;
        if frame.payload.len() < DETECT_MINIMUM_COMPLETE_PAYLOAD_LEN {
            return Err(Nano3TxError::DetectPayloadTooShortForWorkLevel {
                observed: frame.payload.len(),
                minimum: DETECT_MINIMUM_COMPLETE_PAYLOAD_LEN,
            });
        }

        let first_end = find_nul(frame.payload, DETECT_FIRST_DYNAMIC_FIELD_OFFSET).ok_or(
            Nano3TxError::DetectPayloadMissingTerminator {
                field: "first dynamic identity",
            },
        )?;
        let second_start = first_end + 1;
        let second_end = find_nul(frame.payload, second_start).ok_or(
            Nano3TxError::DetectPayloadMissingTerminator {
                field: "second dynamic identity",
            },
        )?;
        let maximum_index = second_end + 1;
        let maximum = frame.payload.get(maximum_index).copied().ok_or(
            Nano3TxError::DetectPayloadMissingWorkLevelMaximum {
                required_index: maximum_index,
                observed: frame.payload.len(),
            },
        )?;

        Ok(Self {
            sync_identity,
            work_level_maximum: DetectedWorkLevelMaximum(maximum),
        })
    }

    pub const fn sync_identity(self) -> SyncIdentity {
        self.sync_identity
    }

    pub const fn work_level_maximum(self) -> DetectedWorkLevelMaximum {
        self.work_level_maximum
    }
}

/// Binary-proven fields of the type-0x20 work-parameter packet.
///
/// No caller supplies nonce2 start/range or the fixed merkle offset.  They are
/// derived exactly as stock does, which prevents arbitrary work-field bytes
/// from entering this serializer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobParameters {
    pub coinbase_len: u32,
    pub nonce2_offset: u32,
    /// Only the two layouts fully bounded by the held binary are admitted.
    pub nonce2_size: u8,
    pub merkle_branch_count: u8,
    pub device_index: u32,
    pub total_devices: u32,
    pub restart: bool,
}

/// The four semantic Bitcoin header-version words sent by stock type 0x27.
///
/// The held binary reads `pool->vmask_001` at indices 0, 2, 4, and 8 in this
/// order. Canaan's held source proves those pool words are byte-swapped before
/// storage, so their raw little-endian memory bytes are the semantic version
/// words in big-endian wire order. Callers therefore provide normal host-order
/// `u32` versions; this serializer owns the byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRollingWords {
    pub micro_job_0: u32,
    pub micro_job_2: u32,
    pub micro_job_4: u32,
    pub micro_job_8: u32,
}

/// Stock's exact 128-byte `pool->header_bin` template for type 0x24.
///
/// The inputs are bytes decoded directly from the corresponding Stratum hex
/// fields: four-byte base version, 32-byte previous hash, four-byte `ntime`,
/// and four-byte `nBits`. Stock inserts a blank merkle root, zero nonce, and
/// the fixed 48-byte SHA-256 work padding. The eventual merkle root and nonce
/// are controller-owned work fields; callers cannot inject either here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StratumHeaderTemplate([u8; WORK_24_BLOCK_LEN]);

impl StratumHeaderTemplate {
    pub const fn from_wire_fields(
        version: [u8; 4],
        previous_hash: [u8; 32],
        ntime: [u8; 4],
        nbits: [u8; 4],
    ) -> Self {
        let mut bytes = [0u8; WORK_24_BLOCK_LEN];
        copy_fixed(&mut bytes, 0, &version);
        copy_fixed(&mut bytes, 4, &previous_hash);
        // bytes 36..68 are stock's blank merkle root.
        copy_fixed(&mut bytes, 68, &ntime);
        copy_fixed(&mut bytes, 72, &nbits);
        // bytes 76..80 are stock's zero nonce.
        copy_fixed(&mut bytes, 80, &SHA256_WORK_PADDING);
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; WORK_24_BLOCK_LEN] {
        &self.0
    }
}

/// The exact 32-bit value stock uses to deduplicate type-0x21 packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobIdentityKey {
    job_id_crc: u16,
    pool_index: u16,
}

impl JobIdentityKey {
    pub fn from_job_id(job_id: &str, pool_index: u16) -> Self {
        Self {
            job_id_crc: crc16_xmodem(job_id.as_bytes()),
            pool_index,
        }
    }

    pub const fn job_id_crc(self) -> u16 {
        self.job_id_crc
    }

    pub const fn pool_index(self) -> u16 {
        self.pool_index
    }

    const fn combined(self) -> u32 {
        (self.job_id_crc as u32) << 16 | self.pool_index as u32
    }
}

/// Stock's zero-initialized `last_jobid` cache for conditional type 0x21.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JobIdentityCache(u32);

impl JobIdentityCache {
    pub const fn after(key: JobIdentityKey) -> Self {
        Self(key.combined())
    }

    pub const fn would_emit(self, key: JobIdentityKey) -> bool {
        self.0 != key.combined()
    }
}

/// Coherent semantic inputs to one offline reconstruction of stock's job trace.
///
/// This is not an I/O plan and carries no transmit authority. Length/count
/// fields are retained in `parameters` because type 0x20 carries them, but the
/// trace builder verifies them against the supplied byte slices before it can
/// return any frames.
#[derive(Debug, Clone, Copy)]
pub struct StockJobTraceInput<'a> {
    pub parameters: JobParameters,
    pub versions: VersionRollingWords,
    pub pool_difficulty: f64,
    pub job_id: &'a str,
    pub pool_index: u16,
    pub coinbase: &'a [u8],
    pub merkle_branches: &'a [[u8; MERKLE_BRANCH_LEN]],
    pub header_template: &'a StratumHeaderTemplate,
}

/// Pure, ordered reconstruction of frames emitted by stock for one job update.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a stock trace grants no authority to transmit its frames"]
pub struct StockJobTrace {
    frames: Vec<Nano3TxFrame>,
    next_identity_cache: JobIdentityCache,
    emitted_identity: bool,
}

impl StockJobTrace {
    pub fn frames(&self) -> &[Nano3TxFrame] {
        &self.frames
    }

    pub fn into_frames(self) -> Vec<Nano3TxFrame> {
        self.frames
    }

    pub const fn next_identity_cache(&self) -> JobIdentityCache {
        self.next_identity_cache
    }

    pub const fn emitted_identity(&self) -> bool {
        self.emitted_identity
    }
}

/// Immutable material needed to rebuild and validate a returned Nano 3 share.
///
/// Fields are private and this module exposes no public constructor. A value
/// can only be derived from one coherent, sealed-capability stock job input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nano3ShareJob {
    parameters: JobParameters,
    versions: VersionRollingWords,
    coinbase: Vec<u8>,
    merkle_branches: Vec<[u8; MERKLE_BRANCH_LEN]>,
    header_template: StratumHeaderTemplate,
    assigned_target: [u8; 32],
}

impl Nano3ShareJob {
    pub const fn assigned_target(&self) -> &[u8; 32] {
        &self.assigned_target
    }
}

/// A nonce whose exact reconstructed header satisfies both stock's diff-1
/// prefilter and the pool's actual (unclamped) assigned target.
///
/// This is evidence only. It grants no authority to submit a share, transmit
/// to a controller, or bypass the still-closed native-TX gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "cryptographic validation grants no share-submission or transmit authority"]
pub struct CryptographicallyValidatedNonce {
    record: crate::nano3_uart::NonceRecord,
    job_generation: u64,
    history_slot: usize,
    header: [u8; 80],
    hash: [u8; 32],
    assigned_target: [u8; 32],
}

impl CryptographicallyValidatedNonce {
    pub const fn record(&self) -> crate::nano3_uart::NonceRecord {
        self.record
    }

    pub const fn job_generation(&self) -> u64 {
        self.job_generation
    }

    pub const fn history_slot(&self) -> usize {
        self.history_slot
    }

    pub const fn header(&self) -> &[u8; 80] {
        &self.header
    }

    /// Raw SHA-256d digest bytes, before Bitcoin display-order reversal.
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    pub const fn assigned_target(&self) -> &[u8; 32] {
        &self.assigned_target
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Nano3ShareError {
    #[error("Nano 3 nonce micro-job id {0} escaped structural admission")]
    UnsupportedMidId(u8),

    #[error("Nano 3 nonce2 value 0x{value:08x} does not fit the proven {size}-byte field")]
    Nonce2DoesNotFit { value: u32, size: u8 },

    #[error("Nano 3 rolled ntime overflows: base 0x{base:08x}, offset {offset}")]
    NtimeOverflow { base: u32, offset: u8 },

    #[error("Nano 3 nonce does not satisfy stock's difficulty-one prefilter")]
    DoesNotMeetStockDifficultyOne,

    #[error("Nano 3 nonce does not satisfy the pool's assigned share target")]
    DoesNotMeetAssignedTarget,

    #[error("Nano 3 share job snapshot invariant failed: {0}")]
    InconsistentJobSnapshot(&'static str),
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Nano3TxError {
    #[error("expected a type-0x11 Nano 3 detect acknowledgement, got 0x{0:02x}")]
    UnexpectedDetectResponseType(u8),

    #[error(
        "Nano 3 detect payload is too short for the proven sync identity: expected at least {required}, got {observed}"
    )]
    DetectPayloadTooShort { observed: usize, required: usize },

    #[error(
        "Nano 3 detect payload is too short for the work-level field: expected at least {minimum}, got {observed}"
    )]
    DetectPayloadTooShortForWorkLevel { observed: usize, minimum: usize },

    #[error("Nano 3 detect payload has no terminator for {field}")]
    DetectPayloadMissingTerminator { field: &'static str },

    #[error(
        "Nano 3 detect payload has no work-level maximum at index {required_index}; payload length is {observed}"
    )]
    DetectPayloadMissingWorkLevelMaximum {
        required_index: usize,
        observed: usize,
    },

    #[error("expected a type-0x13 Nano 3 sync acknowledgement, got 0x{0:02x}")]
    UnexpectedSyncResponseType(u8),

    #[error(
        "Nano 3 nonce2 size {0} is unresolved; only exact 3-byte and 4-byte layouts are admitted"
    )]
    UnsupportedNonce2Size(u8),

    #[error("Nano 3 work parameters require a nonzero total device count")]
    ZeroTotalDevices,

    #[error("Nano 3 device index {device_index} is outside total device count {total_devices}")]
    DeviceIndexOutOfRange {
        device_index: u32,
        total_devices: u32,
    },

    #[error("Nano 3 nonce2 range is empty for size {nonce2_size} across {total_devices} devices")]
    EmptyNonce2Range { nonce2_size: u8, total_devices: u32 },

    #[error(
        "Nano 3 nonce2 region offset {offset} plus size {size} exceeds coinbase length {coinbase_len}"
    )]
    Nonce2OutsideCoinbase {
        offset: u32,
        size: u8,
        coinbase_len: u32,
    },

    #[error("Nano 3 modified coinbase tail {observed} exceeds stock maximum {maximum} bytes")]
    ModifiedCoinbaseTailTooLong { observed: u32, maximum: u32 },

    #[error("Nano 3 coinbase must not be empty")]
    EmptyCoinbase,

    #[error(
        "Nano 3 type-0x20 coinbase length {declared} does not match supplied bytes {observed}"
    )]
    CoinbaseLengthMismatch { declared: u32, observed: usize },

    #[error(
        "Nano 3 type-0x20 merkle count {declared} does not match supplied branches {observed}"
    )]
    MerkleCountMismatch { declared: u8, observed: usize },

    #[error("Nano 3 merkle branch count {observed} exceeds stock maximum {maximum}")]
    TooManyMerkleBranches { observed: usize, maximum: usize },

    #[error(
        "Nano 3 {kind} fragment count {observed} exceeds the proven one-byte maximum {maximum}"
    )]
    TooManyFragments {
        kind: &'static str,
        observed: usize,
        maximum: usize,
    },

    #[error("Nano 3 pool difficulty must be finite and positive")]
    InvalidPoolDifficulty,

    #[error("Nano 3 pool difficulty produces a target outside the stock 256-bit contract")]
    UnrepresentablePoolDifficulty,

    #[error(
        "complete Nano 3 init serialization is refused: live acknowledgement behavior and safe controller sequencing remain unresolved"
    )]
    CompleteInitContractUnresolved,

    #[error(
        "complete Nano 3 job serialization is refused: live acknowledgement behavior and safe controller sequencing remain unresolved"
    )]
    CompleteJobContractUnresolved,

    #[error(
        "Nano 3 native TX is not authorized: independent cut, cooling/thermal/watchdog custody, and live protocol validation are incomplete"
    )]
    NativeTxNotAuthorized,
}

/// Sealed capability required by every research frame constructor.
///
/// This type deliberately has no public constructor. Enabling the
/// `nano3-native-tx-research` Cargo feature exposes the proven byte layouts for
/// review, but does not give a downstream crate a safe-Rust path to serialize
/// a frame. A future bench-only constructor must land as a separately reviewed
/// authority boundary; it must not be inferred from the feature flag.
///
/// ```compile_fail
/// use dcent_avalon_proto::nano3_uart_tx::{
///     detect_request, Nano3TxResearchCapability,
/// };
///
/// // The sealing field is private to this module.
/// let capability = Nano3TxResearchCapability { _sealed: () };
/// let _frame = detect_request(&capability);
/// ```
///
/// ```compile_fail
/// use dcent_avalon_proto::nano3_uart_tx::Nano3TxResearchCapability;
///
/// // There is also intentionally no public constructor.
/// let _capability = Nano3TxResearchCapability::new();
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub struct Nano3TxResearchCapability {
    _sealed: (),
}

impl Nano3TxResearchCapability {
    /// Crate-internal capability for code that compares already captured bytes.
    ///
    /// This remains inaccessible to downstream crates and must never escape in
    /// a public return value. The transcript validator uses it only to derive
    /// expected bytes, then returns evidence without frames or TX authority.
    pub(crate) const fn for_offline_transcript_validation() -> Self {
        Self { _sealed: () }
    }

    #[cfg(test)]
    pub(crate) const fn for_unit_tests() -> Self {
        Self::for_offline_transcript_validation()
    }
}

/// Exact stock detect request: type 0x10, one four-byte zero payload.
pub fn detect_request(_capability: &Nano3TxResearchCapability) -> Nano3TxFrame {
    encode_frame(TYPE_DETECT, 0, 1, &[0; 4])
}

/// Exact stock sync request derived from the immediately preceding detect ack.
pub fn sync_request(
    _capability: &Nano3TxResearchCapability,
    identity: SyncIdentity,
) -> Nano3TxFrame {
    let mut payload = [0u8; SYNC_IDENTITY_LEN + 1];
    payload[..SYNC_IDENTITY_LEN].copy_from_slice(&identity.0);
    payload[SYNC_IDENTITY_LEN] = 1;
    encode_frame(TYPE_SYNC, 0, 1, &payload)
}

/// Verify the only response fact stock checks after a sync request.
pub fn verify_sync_ack(frame: &RxFrame<'_>) -> Result<(), Nano3TxError> {
    if frame.packet_type != RxType::SyncAck {
        return Err(Nano3TxError::UnexpectedSyncResponseType(
            frame.packet_type as u8,
        ));
    }
    Ok(())
}

/// Exact empty type-0x31 frame sent after stock's detect/init routine.
///
/// This frame is not a shutdown primitive and does not complete init on its
/// own; `require_complete_init_contract` remains a refusal.
pub fn init_finish(_capability: &Nano3TxResearchCapability) -> Nano3TxFrame {
    encode_frame(TYPE_INIT_FINISH, 0, 1, &[])
}

/// The only proven read-only poll selector.  The zero payload is kept inside a
/// parameter-free constructor so a reset selector cannot be passed by mistake.
pub fn read_only_poll(_capability: &Nano3TxResearchCapability) -> Nano3TxFrame {
    encode_frame(TYPE_READ_ONLY_POLL, 0, 1, &[0; 4])
}

/// Derive and serialize stock's exact type-0x41 work-level selection.
///
/// `detect_modules` uses the requested persistent level only when it is
/// strictly below the maximum reported by the detect acknowledgement;
/// otherwise it falls back to level 1. The payload is one little-endian u32.
/// This proves stock compatibility only and grants no power or TX authority.
pub fn work_level(
    _capability: &Nano3TxResearchCapability,
    requested: u8,
    detected_maximum: DetectedWorkLevelMaximum,
) -> Nano3TxFrame {
    let selected = if requested < detected_maximum.0 {
        requested
    } else {
        1
    };
    encode_frame(TYPE_WORK_LEVEL, 0, 1, &u32::from(selected).to_le_bytes())
}

/// Verify sync and reconstruct stock's two post-sync init transmissions.
///
/// This pure trace contains no retry scheduler, delays, transport, or authority.
pub fn stock_post_sync_init_trace(
    capability: &Nano3TxResearchCapability,
    detect: DetectAckContract,
    sync_ack: &RxFrame<'_>,
    requested_work_level: u8,
) -> Result<[Nano3TxFrame; 2], Nano3TxError> {
    verify_sync_ack(sync_ack)?;
    Ok([
        work_level(
            capability,
            requested_work_level,
            detect.work_level_maximum(),
        ),
        init_finish(capability),
    ])
}

/// Serialize the exact type-0x20 work-parameter layout.
pub fn job_parameters(
    _capability: &Nano3TxResearchCapability,
    parameters: JobParameters,
) -> Result<Nano3TxFrame, Nano3TxError> {
    if !matches!(parameters.nonce2_size, 3 | 4) {
        return Err(Nano3TxError::UnsupportedNonce2Size(parameters.nonce2_size));
    }
    validate_merkle_count(usize::from(parameters.merkle_branch_count))?;
    if parameters.total_devices == 0 {
        return Err(Nano3TxError::ZeroTotalDevices);
    }
    if parameters.device_index >= parameters.total_devices {
        return Err(Nano3TxError::DeviceIndexOutOfRange {
            device_index: parameters.device_index,
            total_devices: parameters.total_devices,
        });
    }
    let nonce2_end = parameters
        .nonce2_offset
        .checked_add(u32::from(parameters.nonce2_size))
        .ok_or(Nano3TxError::Nonce2OutsideCoinbase {
            offset: parameters.nonce2_offset,
            size: parameters.nonce2_size,
            coinbase_len: parameters.coinbase_len,
        })?;
    if nonce2_end > parameters.coinbase_len {
        return Err(Nano3TxError::Nonce2OutsideCoinbase {
            offset: parameters.nonce2_offset,
            size: parameters.nonce2_size,
            coinbase_len: parameters.coinbase_len,
        });
    }
    let nonce2_sha_boundary =
        parameters.nonce2_offset - parameters.nonce2_offset % SHA256_BLOCK_LEN;
    let modified_coinbase_tail = parameters.coinbase_len - nonce2_sha_boundary;
    if modified_coinbase_tail > MAX_MODIFIED_COINBASE_TAIL_LEN {
        return Err(Nano3TxError::ModifiedCoinbaseTailTooLong {
            observed: modified_coinbase_tail,
            maximum: MAX_MODIFIED_COINBASE_TAIL_LEN,
        });
    }

    let nonce2_span = if parameters.nonce2_size == 3 {
        NONCE2_SIZE_THREE_RANGE
    } else {
        u32::MAX
    };
    let nonce2_range = nonce2_span / parameters.total_devices;
    if nonce2_range == 0 {
        return Err(Nano3TxError::EmptyNonce2Range {
            nonce2_size: parameters.nonce2_size,
            total_devices: parameters.total_devices,
        });
    }
    let nonce2_start = parameters.device_index * nonce2_range;

    let mut payload = Vec::with_capacity(if parameters.restart { 32 } else { 28 });
    for value in [
        parameters.coinbase_len,
        parameters.nonce2_offset,
        u32::from(parameters.nonce2_size),
        MERKLE_OFFSET,
        u32::from(parameters.merkle_branch_count),
        nonce2_start,
        nonce2_range,
    ] {
        payload.extend_from_slice(&value.to_be_bytes());
    }
    if parameters.restart {
        payload.extend_from_slice(&1u32.to_be_bytes());
    }
    Ok(encode_frame(TYPE_JOB_PARAMETERS, 0, 1, &payload))
}

/// Serialize the exact type-0x27 version-rolling words.
pub fn version_rolling_words(
    _capability: &Nano3TxResearchCapability,
    words: VersionRollingWords,
) -> Nano3TxFrame {
    let mut payload = [0u8; 16];
    for (chunk, value) in payload.chunks_exact_mut(4).zip([
        words.micro_job_0,
        words.micro_job_2,
        words.micro_job_4,
        words.micro_job_8,
    ]) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    encode_frame(TYPE_VERSION_WORDS, 0, 1, &payload)
}

/// Derive stock's exact little-endian 256-bit target from pool difficulty.
///
/// The held binary first clamps difficulty to 4096, then executes cgminer's
/// four-limb IEEE-754 `set_target` algorithm. Invalid values are refused
/// rather than inheriting C's undefined/saturating conversion edge cases.
pub fn target_from_pool_difficulty(pool_difficulty: f64) -> Result<[u8; 32], Nano3TxError> {
    if !pool_difficulty.is_finite() || pool_difficulty <= 0.0 {
        return Err(Nano3TxError::InvalidPoolDifficulty);
    }
    target_from_effective_difficulty(pool_difficulty.min(STOCK_MAX_TARGET_DIFFICULTY))
}

/// Derive cgminer's little-endian share target without the controller's 4096
/// difficulty cap. Stock uses this actual pool target when validating a nonce
/// before submission, even though type 0x25 sends the capped controller target.
fn share_target_from_pool_difficulty(pool_difficulty: f64) -> Result<[u8; 32], Nano3TxError> {
    target_from_effective_difficulty(pool_difficulty)
}

fn target_from_effective_difficulty(effective_difficulty: f64) -> Result<[u8; 32], Nano3TxError> {
    if !effective_difficulty.is_finite() || effective_difficulty <= 0.0 {
        return Err(Nano3TxError::InvalidPoolDifficulty);
    }

    let mut remaining = TRUE_DIFF_ONE / effective_difficulty;
    let take_limb = |remaining: &mut f64, scale: f64| -> Result<u64, Nano3TxError> {
        let quotient = *remaining / scale;
        if !quotient.is_finite() || !(0.0..BITS_64).contains(&quotient) {
            return Err(Nano3TxError::UnrepresentablePoolDifficulty);
        }
        let limb = quotient as u64;
        *remaining -= (limb as f64) * scale;
        if !remaining.is_finite() || *remaining < 0.0 {
            return Err(Nano3TxError::UnrepresentablePoolDifficulty);
        }
        Ok(limb)
    };
    let high = take_limb(&mut remaining, BITS_192)?;
    let mid_high = take_limb(&mut remaining, BITS_128)?;
    let mid_low = take_limb(&mut remaining, BITS_64)?;
    let low = take_limb(&mut remaining, 1.0)?;

    let mut target = [0u8; 32];
    for (chunk, limb) in target
        .chunks_exact_mut(8)
        .zip([low, mid_low, mid_high, high])
    {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    Ok(target)
}

/// Serialize type 0x25 from stock's bounded pool-difficulty derivation.
pub fn job_target(
    _capability: &Nano3TxResearchCapability,
    pool_difficulty: f64,
) -> Result<Nano3TxFrame, Nano3TxError> {
    let target = target_from_pool_difficulty(pool_difficulty)?;
    Ok(encode_frame(TYPE_TARGET, 0, 1, &target))
}

/// Serialize the exact type-0x21 job CRC/pool identity packet.
pub fn job_identity(
    capability: &Nano3TxResearchCapability,
    job_id: &str,
    pool_index: u16,
) -> Nano3TxFrame {
    job_identity_from_key(capability, JobIdentityKey::from_job_id(job_id, pool_index))
}

/// Reproduce stock's `last_jobid` comparison for conditional type 0x21.
pub fn conditional_job_identity(
    capability: &Nano3TxResearchCapability,
    previous: JobIdentityCache,
    current: JobIdentityKey,
) -> Option<Nano3TxFrame> {
    previous
        .would_emit(current)
        .then(|| job_identity_from_key(capability, current))
}

fn job_identity_from_key(
    _capability: &Nano3TxResearchCapability,
    key: JobIdentityKey,
) -> Nano3TxFrame {
    let mut payload = [0u8; 4];
    payload[..2].copy_from_slice(&key.job_id_crc.to_be_bytes());
    payload[2..].copy_from_slice(&key.pool_index.to_le_bytes());
    encode_frame(TYPE_JOB_IDENTITY, 0, 1, &payload)
}

/// Split coinbase bytes exactly as stock type 0x22 does.
pub fn coinbase_fragments(
    _capability: &Nano3TxResearchCapability,
    coinbase: &[u8],
) -> Result<Vec<Nano3TxFrame>, Nano3TxError> {
    if coinbase.is_empty() {
        return Err(Nano3TxError::EmptyCoinbase);
    }
    let count = coinbase.len().div_ceil(COINBASE_FRAGMENT_LEN);
    ensure_fragment_count("coinbase", count)?;

    Ok(coinbase
        .chunks(COINBASE_FRAGMENT_LEN)
        .enumerate()
        .map(|(index, payload)| encode_frame(TYPE_COINBASE, index as u16, count as u16, payload))
        .collect())
}

/// Serialize exact 32-byte type-0x23 merkle-branch packets.
pub fn merkle_fragments(
    _capability: &Nano3TxResearchCapability,
    branches: &[[u8; MERKLE_BRANCH_LEN]],
) -> Result<Vec<Nano3TxFrame>, Nano3TxError> {
    validate_merkle_count(branches.len())?;
    Ok(branches
        .iter()
        .enumerate()
        .map(|(index, branch)| {
            encode_frame(TYPE_MERKLE, index as u16, branches.len() as u16, branch)
        })
        .collect())
}

/// Serialize stock's exact 128-byte header template as four type-0x24 chunks.
pub fn work_24_fragments(
    _capability: &Nano3TxResearchCapability,
    template: &StratumHeaderTemplate,
) -> [Nano3TxFrame; WORK_24_CHUNK_COUNT] {
    core::array::from_fn(|index| {
        let start = index * MERKLE_BRANCH_LEN;
        encode_frame(
            TYPE_WORK_24,
            index as u16,
            WORK_24_CHUNK_COUNT as u16,
            &template.0[start..start + MERKLE_BRANCH_LEN],
        )
    })
}

/// Build the exact ordered frame trace stock emits for one coherent job.
///
/// This proves offline serialization/order only. It deliberately does not
/// satisfy `require_complete_job_contract` and has no transport or timing
/// behavior. The returned trace remains behind the sealed research capability.
pub fn stock_job_trace(
    capability: &Nano3TxResearchCapability,
    previous_identity: JobIdentityCache,
    input: StockJobTraceInput<'_>,
) -> Result<StockJobTrace, Nano3TxError> {
    if u32::try_from(input.coinbase.len()).ok() != Some(input.parameters.coinbase_len) {
        return Err(Nano3TxError::CoinbaseLengthMismatch {
            declared: input.parameters.coinbase_len,
            observed: input.coinbase.len(),
        });
    }
    if usize::from(input.parameters.merkle_branch_count) != input.merkle_branches.len() {
        return Err(Nano3TxError::MerkleCountMismatch {
            declared: input.parameters.merkle_branch_count,
            observed: input.merkle_branches.len(),
        });
    }

    let parameters = job_parameters(capability, input.parameters)?;
    let target = job_target(capability, input.pool_difficulty)?;
    let coinbase = coinbase_fragments(capability, input.coinbase)?;
    let merkle = merkle_fragments(capability, input.merkle_branches)?;
    let header = work_24_fragments(capability, input.header_template);
    let identity = JobIdentityKey::from_job_id(input.job_id, input.pool_index);
    let identity_frame = conditional_job_identity(capability, previous_identity, identity);
    let emitted_identity = identity_frame.is_some();

    let mut frames = Vec::with_capacity(
        4 + usize::from(emitted_identity) + coinbase.len() + merkle.len() + header.len(),
    );
    frames.push(parameters);
    frames.push(version_rolling_words(capability, input.versions));
    frames.push(target);
    frames.extend(identity_frame);
    frames.extend(coinbase);
    frames.extend(merkle);
    frames.extend(header);
    frames.push(job_finish(capability));

    Ok(StockJobTrace {
        frames,
        next_identity_cache: JobIdentityCache::after(identity),
        emitted_identity,
    })
}

/// Retain an immutable share-validation snapshot from one coherent stock job.
///
/// Construction reuses the complete offline job-trace validation, then derives
/// the actual unclamped pool target used by stock's CPU-side share check. The
/// returned value contains no transport handle or submission authority.
pub fn share_job_snapshot(
    capability: &Nano3TxResearchCapability,
    input: StockJobTraceInput<'_>,
) -> Result<Nano3ShareJob, Nano3TxError> {
    let _validated_trace = stock_job_trace(capability, JobIdentityCache::default(), input)?;
    let assigned_target = share_target_from_pool_difficulty(input.pool_difficulty)?;

    Ok(Nano3ShareJob {
        parameters: input.parameters,
        versions: input.versions,
        coinbase: input.coinbase.to_vec(),
        merkle_branches: input.merkle_branches.to_vec(),
        header_template: *input.header_template,
        assigned_target,
    })
}

/// Rebuild and validate a structurally admitted nonce exactly as stock does.
///
/// The reconstruction inserts nonce2 little-endian, hashes the coinbase and
/// merkle path, applies the type-0x27 micro-job version and ntime offset, then
/// performs stock's per-word header flip and double SHA-256. Success requires
/// both the stock difficulty-one prefilter and the actual pool share target.
pub fn verify_share_candidate(
    candidate: StructurallyAdmittedNonce<'_, Nano3ShareJob>,
) -> Result<CryptographicallyValidatedNonce, Nano3ShareError> {
    let record = candidate.record();
    let header = rebuild_share_header(&candidate.matched_job().job, record)?;
    let hash = double_sha256(&header);

    if hash[28..].iter().any(|&byte| byte != 0) {
        return Err(Nano3ShareError::DoesNotMeetStockDifficultyOne);
    }

    let assigned_target = candidate.matched_job().job.assigned_target;
    if !little_endian_hash_meets_target(&hash, &assigned_target) {
        return Err(Nano3ShareError::DoesNotMeetAssignedTarget);
    }

    Ok(CryptographicallyValidatedNonce {
        record,
        job_generation: candidate.matched_job().identity.generation,
        history_slot: candidate.history_slot(),
        header,
        hash,
        assigned_target,
    })
}

fn rebuild_share_header(
    job: &Nano3ShareJob,
    record: crate::nano3_uart::NonceRecord,
) -> Result<[u8; 80], Nano3ShareError> {
    let version = match record.mid_id {
        0 => job.versions.micro_job_0,
        1 => job.versions.micro_job_2,
        2 => job.versions.micro_job_4,
        3 => job.versions.micro_job_8,
        other => return Err(Nano3ShareError::UnsupportedMidId(other)),
    };

    let mut coinbase = job.coinbase.clone();
    let nonce2_offset = usize::try_from(job.parameters.nonce2_offset)
        .map_err(|_| Nano3ShareError::InconsistentJobSnapshot("nonce2 offset"))?;
    let nonce2_len = usize::from(job.parameters.nonce2_size);
    let nonce2_end = nonce2_offset
        .checked_add(nonce2_len)
        .ok_or(Nano3ShareError::InconsistentJobSnapshot("nonce2 range"))?;
    let nonce2_region = coinbase.get_mut(nonce2_offset..nonce2_end).ok_or(
        Nano3ShareError::InconsistentJobSnapshot("nonce2 outside coinbase"),
    )?;
    let nonce2_bytes = record.nonce2.to_le_bytes();
    match job.parameters.nonce2_size {
        3 => {
            if record.nonce2 > NONCE2_SIZE_THREE_RANGE {
                return Err(Nano3ShareError::Nonce2DoesNotFit {
                    value: record.nonce2,
                    size: 3,
                });
            }
            nonce2_region.copy_from_slice(&nonce2_bytes[..3]);
        }
        4 => nonce2_region.copy_from_slice(&nonce2_bytes),
        _ => {
            return Err(Nano3ShareError::InconsistentJobSnapshot(
                "unsupported nonce2 size",
            ));
        }
    }

    let mut merkle_root = double_sha256(&coinbase);
    for branch in &job.merkle_branches {
        let mut pair = [0u8; 2 * MERKLE_BRANCH_LEN];
        pair[..MERKLE_BRANCH_LEN].copy_from_slice(&merkle_root);
        pair[MERKLE_BRANCH_LEN..].copy_from_slice(branch);
        merkle_root = double_sha256(&pair);
    }

    let mut work = job.header_template.0;
    work[..4].copy_from_slice(&version.to_be_bytes());
    for (destination, source) in work[36..68]
        .chunks_exact_mut(4)
        .zip(merkle_root.chunks_exact(4))
    {
        destination.copy_from_slice(&[source[3], source[2], source[1], source[0]]);
    }

    let base_ntime = u32::from_be_bytes([work[68], work[69], work[70], work[71]]);
    let rolled_ntime = base_ntime
        .checked_add(u32::from(record.ntime_offset))
        .ok_or(Nano3ShareError::NtimeOverflow {
            base: base_ntime,
            offset: record.ntime_offset,
        })?;
    work[68..72].copy_from_slice(&rolled_ntime.to_be_bytes());
    work[76..80].copy_from_slice(&record.nonce.to_le_bytes());

    let mut header = [0u8; 80];
    for (destination, source) in header.chunks_exact_mut(4).zip(work[..80].chunks_exact(4)) {
        destination.copy_from_slice(&[source[3], source[2], source[1], source[0]]);
    }
    Ok(header)
}

fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    Sha256::digest(first).into()
}

fn little_endian_hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for index in (0..hash.len()).rev() {
        match hash[index].cmp(&target[index]) {
            core::cmp::Ordering::Less => return true,
            core::cmp::Ordering::Greater => return false,
            core::cmp::Ordering::Equal => {}
        }
    }
    true
}

/// Exact empty type-0x26 packet ending stock's work upload.
pub fn job_finish(_capability: &Nano3TxResearchCapability) -> Nano3TxFrame {
    encode_frame(TYPE_JOB_FINISH, 0, 1, &[])
}

/// Fail-closed marker for the not-yet-live-qualified init contract.
pub fn require_complete_init_contract() -> Result<(), Nano3TxError> {
    Err(Nano3TxError::CompleteInitContractUnresolved)
}

/// Fail-closed marker for the not-yet-live-qualified job contract.
pub fn require_complete_job_contract() -> Result<(), Nano3TxError> {
    Err(Nano3TxError::CompleteJobContractUnresolved)
}

/// Fail-closed native transmit authority gate.
pub fn require_native_tx_authority() -> Result<(), Nano3TxError> {
    Err(Nano3TxError::NativeTxNotAuthorized)
}

fn ensure_fragment_count(kind: &'static str, count: usize) -> Result<(), Nano3TxError> {
    if count > MAX_FRAGMENT_COUNT {
        return Err(Nano3TxError::TooManyFragments {
            kind,
            observed: count,
            maximum: MAX_FRAGMENT_COUNT,
        });
    }
    Ok(())
}

fn find_nul(bytes: &[u8], start: usize) -> Option<usize> {
    bytes
        .get(start..)?
        .iter()
        .position(|byte| *byte == 0)
        .map(|relative| start + relative)
}

fn validate_merkle_count(count: usize) -> Result<(), Nano3TxError> {
    if count > MAX_MERKLE_BRANCH_COUNT {
        return Err(Nano3TxError::TooManyMerkleBranches {
            observed: count,
            maximum: MAX_MERKLE_BRANCH_COUNT,
        });
    }
    Ok(())
}

const fn sha256_work_padding() -> [u8; 48] {
    let mut padding = [0u8; 48];
    // Exact bytes decoded from cgminer's 96-character `workpadding` string.
    padding[3] = 0x80;
    padding[44] = 0x80;
    padding[45] = 0x02;
    padding
}

const fn copy_fixed<const N: usize>(
    target: &mut [u8; WORK_24_BLOCK_LEN],
    offset: usize,
    source: &[u8; N],
) {
    let mut index = 0;
    while index < N {
        target[offset + index] = source[index];
        index += 1;
    }
}

fn encode_frame(packet_type: u8, index: u16, count: u16, payload: &[u8]) -> Nano3TxFrame {
    // Every public caller fixes payload size at or below the 128-byte held
    // receiver limit.  Keep this assertion next to the sole envelope writer.
    assert!(payload.len() <= crate::nano3_uart::MAX_PAYLOAD_LEN);

    let len = HEADER_LEN + payload.len();
    let mut bytes = [0u8; MAX_FRAME_LEN];
    bytes[..2].copy_from_slice(&MAGIC);
    bytes[4] = packet_type;
    // byte 5 (option) is zero for every proven constructor in this module.
    bytes[6..8].copy_from_slice(&index.to_le_bytes());
    bytes[8..10].copy_from_slice(&count.to_le_bytes());
    bytes[10..12].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    bytes[HEADER_LEN..len].copy_from_slice(payload);
    let crc = crc16_xmodem(&bytes[4..len]);
    bytes[2..4].copy_from_slice(&crc.to_le_bytes());
    Nano3TxFrame { bytes, len }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nano3_uart::{decode_rx_frame, NonceRecord};
    use crate::nano3_uart_rx::{Nano3JobIdentity, Nano3RecentJobs, NANO3_ASIC_COUNT};
    use std::collections::BTreeMap;

    fn research_capability() -> Nano3TxResearchCapability {
        Nano3TxResearchCapability::for_unit_tests()
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

    fn held_re_vectors() -> BTreeMap<&'static str, Vec<u8>> {
        include_str!("../tests/fixtures/nano3_tx_re_vectors_v1.txt")
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                let (name, hex) = line
                    .split_once('=')
                    .expect("each held RE vector must be name=hex");
                assert!(!name.is_empty(), "held RE vector name must not be empty");
                assert!(
                    hex.bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                    "held RE vector `{name}` must use canonical lowercase hex"
                );
                Some((name, decode_hex(hex)))
            })
            .collect()
    }

    fn insert_actual_vector(
        vectors: &mut BTreeMap<&'static str, Vec<u8>>,
        name: &'static str,
        frame: Nano3TxFrame,
    ) {
        assert!(
            vectors.insert(name, frame.as_bytes().to_vec()).is_none(),
            "duplicate actual held RE vector name `{name}`"
        );
    }

    #[test]
    fn sealed_encoder_matches_held_re_trace_corpus_exactly() {
        let capability = research_capability();
        let mut actual = BTreeMap::new();

        insert_actual_vector(&mut actual, "detect", detect_request(&capability));
        insert_actual_vector(
            &mut actual,
            "sync_identity_00_0f",
            sync_request(
                &capability,
                SyncIdentity(core::array::from_fn(|index| index as u8)),
            ),
        );
        insert_actual_vector(
            &mut actual,
            "work_level_requested_2_max_3",
            work_level(&capability, 2, DetectedWorkLevelMaximum(3)),
        );
        insert_actual_vector(&mut actual, "init_finish", init_finish(&capability));
        insert_actual_vector(&mut actual, "read_only_poll", read_only_poll(&capability));

        let coinbase: Vec<u8> = (0..130).map(|value| value as u8).collect();
        let merkle_branches = [core::array::from_fn(|index| index as u8)];
        let header_template = StratumHeaderTemplate::from_wire_fields(
            [0x20, 0, 0, 0],
            [0x11; 32],
            [0x65, 0xaa, 0xbb, 0xcc],
            [0x1d, 0, 0xff, 0xff],
        );
        let trace = stock_job_trace(
            &capability,
            JobIdentityCache::default(),
            StockJobTraceInput {
                parameters: JobParameters {
                    coinbase_len: coinbase.len() as u32,
                    nonce2_offset: 8,
                    nonce2_size: 4,
                    merkle_branch_count: merkle_branches.len() as u8,
                    device_index: 0,
                    total_devices: 1,
                    restart: false,
                },
                versions: VersionRollingWords {
                    micro_job_0: 0x2000_0000,
                    micro_job_2: 0x2000_2000,
                    micro_job_4: 0x2000_4000,
                    micro_job_8: 0x2000_8000,
                },
                pool_difficulty: 1.0,
                job_id: "123456789",
                pool_index: 2,
                coinbase: &coinbase,
                merkle_branches: &merkle_branches,
                header_template: &header_template,
            },
        )
        .unwrap();
        let trace_names = [
            "job_parameters",
            "version_words",
            "target_diff_1",
            "job_identity_123456789_pool_2",
            "coinbase_0",
            "coinbase_1",
            "merkle_0",
            "work_24_0",
            "work_24_1",
            "work_24_2",
            "work_24_3",
            "job_finish",
        ];
        assert_eq!(trace.frames().len(), trace_names.len());
        for (name, frame) in trace_names.into_iter().zip(trace.into_frames()) {
            insert_actual_vector(&mut actual, name, frame);
        }

        let expected = held_re_vectors();
        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
            "the external RE corpus and encoder audit must cover the same exact vector names"
        );
        assert_eq!(actual, expected);
    }

    fn genesis_coinbase() -> Vec<u8> {
        // Constructed from Bitcoin Core's canonical CreateGenesisBlock fields.
        let mut script_sig = vec![0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x45];
        script_sig.extend_from_slice(
            b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
        );
        assert_eq!(script_sig.len(), 77);

        let public_key = decode_hex(concat!(
            "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61de",
            "b649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
        ));
        assert_eq!(public_key.len(), 65);
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
        assert_eq!(transaction.len(), 204);
        transaction
    }

    fn genesis_jobs(
        pool_difficulty: f64,
        nonce2_size: u8,
    ) -> (Nano3RecentJobs<Nano3ShareJob>, Nano3JobIdentity) {
        let coinbase = genesis_coinbase();
        let header_template = StratumHeaderTemplate::from_wire_fields(
            1u32.to_be_bytes(),
            [0; 32],
            0x495f_ab29u32.to_be_bytes(),
            0x1d00_ffffu32.to_be_bytes(),
        );
        let parameters = JobParameters {
            coinbase_len: coinbase.len() as u32,
            nonce2_offset: 5,
            nonce2_size,
            merkle_branch_count: 0,
            device_index: 0,
            total_devices: 1,
            restart: true,
        };
        let versions = VersionRollingWords {
            micro_job_0: 1,
            micro_job_2: 2,
            micro_job_4: 4,
            micro_job_8: 8,
        };
        let snapshot = share_job_snapshot(
            &research_capability(),
            StockJobTraceInput {
                parameters,
                versions,
                pool_difficulty,
                job_id: "genesis",
                pool_index: 0,
                coinbase: &coinbase,
                merkle_branches: &[],
                header_template: &header_template,
            },
        )
        .unwrap();
        let mut jobs = Nano3RecentJobs::new();
        let identity = jobs.remember("genesis", 0, snapshot).unwrap();
        (jobs, identity)
    }

    fn genesis_nonce(identity: Nano3JobIdentity) -> NonceRecord {
        NonceRecord {
            job_id_crc: identity.job_id_crc,
            pool_index: identity.pool_index,
            nonce2: 0,
            // The controller's BE wire word; stock's rebuild/flip path turns
            // this into canonical serialized bytes 1d ac 2b 7c.
            nonce: 0x1dac_2b7c,
            asic_id: 0,
            miner_id: 0,
            ntime_offset: 0,
            mid_id: 0,
            valid_marker: 1,
        }
    }

    fn rx_fixture(packet_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![MAGIC[0], MAGIC[1], 0, 0, packet_type, 0, 0, 0, 1, 0];
        bytes.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        bytes.extend_from_slice(payload);
        let crc = crc16_xmodem(&bytes[4..]);
        bytes[2..4].copy_from_slice(&crc.to_le_bytes());
        bytes
    }

    fn complete_detect_ack(first_dynamic: &[u8], second_dynamic: &[u8], maximum: u8) -> Vec<u8> {
        let mut payload = vec![0xa5; DETECT_FIRST_DYNAMIC_FIELD_OFFSET];
        payload[SYNC_IDENTITY_DETECT_PAYLOAD_OFFSET..DETECT_IDENTITY_END].copy_from_slice(
            &core::array::from_fn::<_, SYNC_IDENTITY_LEN, _>(|index| index as u8),
        );
        payload.extend_from_slice(first_dynamic);
        payload.push(0);
        payload.extend_from_slice(second_dynamic);
        payload.push(0);
        payload.push(maximum);
        rx_fixture(RxType::DetectAck as u8, &payload)
    }

    fn detect_contract(maximum: u8) -> DetectAckContract {
        let bytes = complete_detect_ack(b"model", b"firmware", maximum);
        let frame = decode_rx_frame(&bytes).unwrap();
        DetectAckContract::try_from_detect_ack(&frame).unwrap()
    }

    #[test]
    fn detect_and_read_only_poll_match_held_binary_vectors() {
        assert_eq!(
            detect_request(&research_capability()).as_bytes(),
            [
                0x43, 0x4e, 0x22, 0x76, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ]
        );
        assert_eq!(
            read_only_poll(&research_capability()).as_bytes(),
            [
                0x43, 0x4e, 0x1d, 0x1d, 0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ]
        );
    }

    #[test]
    fn sync_copies_only_the_proven_detect_ack_identity_window() {
        let mut payload = vec![0xaa; 4];
        payload.extend(0u8..16);
        payload.extend_from_slice(&[0xbb; 12]);
        let bytes = rx_fixture(RxType::DetectAck as u8, &payload);
        let ack = decode_rx_frame(&bytes).unwrap();
        let identity = SyncIdentity::try_from_detect_ack(&ack).unwrap();

        assert_eq!(
            sync_request(&research_capability(), identity).as_bytes(),
            [
                0x43, 0x4e, 0xed, 0xcc, 0x12, 0x00, 0x00, 0x00, 0x01, 0x00, 0x11, 0x00, 0x00, 0x01,
                0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x01,
            ]
        );
    }

    #[test]
    fn sync_identity_rejects_wrong_type_and_short_detect_payload() {
        let wrong = rx_fixture(RxType::SyncAck as u8, &[0; DETECT_IDENTITY_END]);
        let wrong = decode_rx_frame(&wrong).unwrap();
        assert_eq!(
            SyncIdentity::try_from_detect_ack(&wrong),
            Err(Nano3TxError::UnexpectedDetectResponseType(0x13))
        );

        let short = rx_fixture(RxType::DetectAck as u8, &[0; DETECT_IDENTITY_END - 1]);
        let short = decode_rx_frame(&short).unwrap();
        assert_eq!(
            SyncIdentity::try_from_detect_ack(&short),
            Err(Nano3TxError::DetectPayloadTooShort {
                observed: DETECT_IDENTITY_END - 1,
                required: DETECT_IDENTITY_END,
            })
        );
    }

    #[test]
    fn complete_detect_ack_derives_sync_identity_and_work_level_maximum() {
        let bytes = complete_detect_ack(b"model", b"firmware", 3);
        let frame = decode_rx_frame(&bytes).unwrap();
        let contract = DetectAckContract::try_from_detect_ack(&frame).unwrap();
        assert_eq!(contract.work_level_maximum().value(), 3);
        assert_eq!(
            sync_request(&research_capability(), contract.sync_identity()).as_bytes(),
            [
                0x43, 0x4e, 0xed, 0xcc, 0x12, 0x00, 0x00, 0x00, 0x01, 0x00, 0x11, 0x00, 0x00, 0x01,
                0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x01,
            ]
        );
        assert_eq!(STOCK_INIT_ATTEMPT_LIMIT, 5);
        assert_eq!(STOCK_INIT_RESPONSE_TIMEOUT_MS, 200);
    }

    #[test]
    fn complete_detect_ack_refuses_truncated_dynamic_layout() {
        let short = rx_fixture(
            RxType::DetectAck as u8,
            &[0; DETECT_MINIMUM_COMPLETE_PAYLOAD_LEN - 1],
        );
        let short = decode_rx_frame(&short).unwrap();
        assert_eq!(
            DetectAckContract::try_from_detect_ack(&short),
            Err(Nano3TxError::DetectPayloadTooShortForWorkLevel {
                observed: DETECT_MINIMUM_COMPLETE_PAYLOAD_LEN - 1,
                minimum: DETECT_MINIMUM_COMPLETE_PAYLOAD_LEN,
            })
        );

        let no_first_terminator = rx_fixture(
            RxType::DetectAck as u8,
            &[1; DETECT_MINIMUM_COMPLETE_PAYLOAD_LEN],
        );
        let no_first_terminator = decode_rx_frame(&no_first_terminator).unwrap();
        assert_eq!(
            DetectAckContract::try_from_detect_ack(&no_first_terminator),
            Err(Nano3TxError::DetectPayloadMissingTerminator {
                field: "first dynamic identity",
            })
        );

        let mut no_second = [1; DETECT_MINIMUM_COMPLETE_PAYLOAD_LEN];
        no_second[DETECT_FIRST_DYNAMIC_FIELD_OFFSET] = 0;
        let no_second = rx_fixture(RxType::DetectAck as u8, &no_second);
        let no_second = decode_rx_frame(&no_second).unwrap();
        assert_eq!(
            DetectAckContract::try_from_detect_ack(&no_second),
            Err(Nano3TxError::DetectPayloadMissingTerminator {
                field: "second dynamic identity",
            })
        );

        let mut no_maximum = [1; DETECT_MINIMUM_COMPLETE_PAYLOAD_LEN];
        no_maximum[DETECT_FIRST_DYNAMIC_FIELD_OFFSET] = 0;
        no_maximum[DETECT_FIRST_DYNAMIC_FIELD_OFFSET + 2] = 0;
        let no_maximum = rx_fixture(RxType::DetectAck as u8, &no_maximum);
        let no_maximum = decode_rx_frame(&no_maximum).unwrap();
        assert_eq!(
            DetectAckContract::try_from_detect_ack(&no_maximum),
            Err(Nano3TxError::DetectPayloadMissingWorkLevelMaximum {
                required_index: DETECT_MINIMUM_COMPLETE_PAYLOAD_LEN,
                observed: DETECT_MINIMUM_COMPLETE_PAYLOAD_LEN,
            })
        );
    }

    #[test]
    fn type_41_applies_stock_strict_maximum_and_little_endian_level() {
        assert_eq!(
            work_level(
                &research_capability(),
                2,
                detect_contract(3).work_level_maximum(),
            )
            .as_bytes(),
            [0x43, 0x4e, 0x2f, 0x72, 0x41, 0, 0, 0, 1, 0, 4, 0, 2, 0, 0, 0,]
        );

        let equal_to_maximum = work_level(
            &research_capability(),
            3,
            detect_contract(3).work_level_maximum(),
        );
        assert_eq!(&equal_to_maximum.as_bytes()[HEADER_LEN..], &[1, 0, 0, 0]);
        let above_maximum = work_level(
            &research_capability(),
            u8::MAX,
            detect_contract(3).work_level_maximum(),
        );
        assert_eq!(&above_maximum.as_bytes()[HEADER_LEN..], &[1, 0, 0, 0]);
    }

    #[test]
    fn post_sync_init_trace_requires_sync_ack_and_uses_detected_maximum() {
        let sync = rx_fixture(RxType::SyncAck as u8, &[]);
        let sync = decode_rx_frame(&sync).unwrap();
        let trace =
            stock_post_sync_init_trace(&research_capability(), detect_contract(3), &sync, 2)
                .unwrap();
        assert_eq!(
            [trace[0].packet_type(), trace[1].packet_type()],
            [TYPE_WORK_LEVEL, TYPE_INIT_FINISH]
        );
        assert_eq!(&trace[0].as_bytes()[HEADER_LEN..], &[2, 0, 0, 0]);

        let wrong = rx_fixture(RxType::DetectAck as u8, &[]);
        let wrong = decode_rx_frame(&wrong).unwrap();
        assert_eq!(
            stock_post_sync_init_trace(&research_capability(), detect_contract(3), &wrong, 2,),
            Err(Nano3TxError::UnexpectedSyncResponseType(0x11))
        );
    }

    #[test]
    fn type_20_three_and_four_byte_nonce2_layouts_are_exact() {
        let four = job_parameters(
            &research_capability(),
            JobParameters {
                coinbase_len: 64,
                nonce2_offset: 8,
                nonce2_size: 4,
                merkle_branch_count: 2,
                device_index: 0,
                total_devices: 1,
                restart: false,
            },
        )
        .unwrap();
        assert_eq!(
            four.as_bytes(),
            [
                0x43, 0x4e, 0x34, 0x48, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x1c, 0x00, 0x00, 0x00,
                0x00, 0x40, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x24,
                0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            ]
        );

        let three_restart = job_parameters(
            &research_capability(),
            JobParameters {
                nonce2_size: 3,
                restart: true,
                ..JobParameters {
                    coinbase_len: 64,
                    nonce2_offset: 8,
                    nonce2_size: 4,
                    merkle_branch_count: 2,
                    device_index: 0,
                    total_devices: 1,
                    restart: false,
                }
            },
        )
        .unwrap();
        assert_eq!(
            three_restart.as_bytes(),
            [
                0x43, 0x4e, 0x25, 0x7b, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00,
                0x00, 0x40, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x24,
                0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00,
                0x00, 0x01,
            ]
        );
    }

    #[test]
    fn type_20_derives_partitioned_nonce2_start_and_range() {
        let frame = job_parameters(
            &research_capability(),
            JobParameters {
                coinbase_len: 64,
                nonce2_offset: 8,
                nonce2_size: 3,
                merkle_branch_count: 0,
                device_index: 1,
                total_devices: 2,
                restart: false,
            },
        )
        .unwrap();
        let payload = &frame.as_bytes()[HEADER_LEN..];
        assert_eq!(&payload[20..24], &0x007f_ffffu32.to_be_bytes());
        assert_eq!(&payload[24..28], &0x007f_ffffu32.to_be_bytes());
    }

    #[test]
    fn type_20_rejects_every_unresolved_or_incoherent_layout() {
        let base = JobParameters {
            coinbase_len: 64,
            nonce2_offset: 8,
            nonce2_size: 4,
            merkle_branch_count: 0,
            device_index: 0,
            total_devices: 1,
            restart: false,
        };
        for size in [0, 1, 2, 5, u8::MAX] {
            assert_eq!(
                job_parameters(
                    &research_capability(),
                    JobParameters {
                        nonce2_size: size,
                        ..base
                    },
                ),
                Err(Nano3TxError::UnsupportedNonce2Size(size))
            );
        }
        assert_eq!(
            job_parameters(
                &research_capability(),
                JobParameters {
                    total_devices: 0,
                    ..base
                },
            ),
            Err(Nano3TxError::ZeroTotalDevices)
        );
        assert_eq!(
            job_parameters(
                &research_capability(),
                JobParameters {
                    device_index: 1,
                    ..base
                },
            ),
            Err(Nano3TxError::DeviceIndexOutOfRange {
                device_index: 1,
                total_devices: 1,
            })
        );
        assert!(matches!(
            job_parameters(
                &research_capability(),
                JobParameters {
                    nonce2_offset: 62,
                    ..base
                },
            ),
            Err(Nano3TxError::Nonce2OutsideCoinbase { .. })
        ));
        assert_eq!(
            job_parameters(
                &research_capability(),
                JobParameters {
                    nonce2_size: 3,
                    total_devices: NONCE2_SIZE_THREE_RANGE + 1,
                    ..base
                },
            ),
            Err(Nano3TxError::EmptyNonce2Range {
                nonce2_size: 3,
                total_devices: NONCE2_SIZE_THREE_RANGE + 1,
            })
        );
        assert_eq!(
            job_parameters(
                &research_capability(),
                JobParameters {
                    merkle_branch_count: (MAX_MERKLE_BRANCH_COUNT + 1) as u8,
                    ..base
                },
            ),
            Err(Nano3TxError::TooManyMerkleBranches {
                observed: MAX_MERKLE_BRANCH_COUNT + 1,
                maximum: MAX_MERKLE_BRANCH_COUNT,
            })
        );
        assert_eq!(
            job_parameters(
                &research_capability(),
                JobParameters {
                    coinbase_len: MAX_MODIFIED_COINBASE_TAIL_LEN + 1,
                    nonce2_offset: 0,
                    ..base
                },
            ),
            Err(Nano3TxError::ModifiedCoinbaseTailTooLong {
                observed: MAX_MODIFIED_COINBASE_TAIL_LEN + 1,
                maximum: MAX_MODIFIED_COINBASE_TAIL_LEN,
            })
        );
    }

    #[test]
    fn type_27_serializes_pool_indices_0_2_4_8_in_semantic_wire_order() {
        let frame = version_rolling_words(
            &research_capability(),
            VersionRollingWords {
                micro_job_0: 0x2000_0000,
                micro_job_2: 0x2000_2000,
                micro_job_4: 0x2000_4000,
                micro_job_8: 0x2000_8000,
            },
        );
        assert_eq!(
            frame.as_bytes(),
            [
                0x43, 0x4e, 0xf4, 0xee, 0x27, 0, 0, 0, 1, 0, 16, 0, 0x20, 0, 0, 0, 0x20, 0, 0x20,
                0, 0x20, 0, 0x40, 0, 0x20, 0, 0x80, 0,
            ]
        );
    }

    #[test]
    fn type_25_matches_cgminer_target_vectors_and_stock_difficulty_cap() {
        let diff_one = job_target(&research_capability(), 1.0).unwrap();
        assert_eq!(
            &diff_one.as_bytes()[..HEADER_LEN],
            &[0x43, 0x4e, 0xe8, 0xf2, 0x25, 0, 0, 0, 1, 0, 32, 0]
        );
        let mut diff_one_target = [0u8; 32];
        diff_one_target[26] = 0xff;
        diff_one_target[27] = 0xff;
        assert_eq!(&diff_one.as_bytes()[HEADER_LEN..], &diff_one_target);

        let capped = job_target(&research_capability(), STOCK_MAX_TARGET_DIFFICULTY).unwrap();
        let above_cap = job_target(&research_capability(), 8192.0).unwrap();
        assert_eq!(capped, above_cap);
        assert_eq!(
            &capped.as_bytes()[..HEADER_LEN],
            &[0x43, 0x4e, 0x07, 0xd1, 0x25, 0, 0, 0, 1, 0, 32, 0]
        );
        let mut capped_target = [0u8; 32];
        capped_target[24..27].copy_from_slice(&[0xf0, 0xff, 0x0f]);
        assert_eq!(&capped.as_bytes()[HEADER_LEN..], &capped_target);

        // Independent Python IEEE-754/CRC-16 XMODEM KAT; unlike the exact
        // divisors above this exercises a non-zero second-highest target limb.
        let irrational = job_target(&research_capability(), core::f64::consts::PI).unwrap();
        assert_eq!(
            &irrational.as_bytes()[..HEADER_LEN],
            &[0x43, 0x4e, 0x58, 0x38, 0x25, 0, 0, 0, 1, 0, 32, 0]
        );
        let mut irrational_target = [0u8; 32];
        irrational_target[21..28].copy_from_slice(&[0xe4, 0x6a, 0x65, 0x3a, 0x70, 0x7c, 0x51]);
        assert_eq!(&irrational.as_bytes()[HEADER_LEN..], &irrational_target);
    }

    #[test]
    fn target_derivation_refuses_invalid_and_unrepresentable_inputs() {
        for invalid in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                target_from_pool_difficulty(invalid),
                Err(Nano3TxError::InvalidPoolDifficulty)
            );
            assert_eq!(
                job_target(&research_capability(), invalid),
                Err(Nano3TxError::InvalidPoolDifficulty)
            );
        }

        for unrepresentable in [1.0e-12, f64::MIN_POSITIVE] {
            assert_eq!(
                target_from_pool_difficulty(unrepresentable),
                Err(Nano3TxError::UnrepresentablePoolDifficulty)
            );
            assert_eq!(
                job_target(&research_capability(), unrepresentable),
                Err(Nano3TxError::UnrepresentablePoolDifficulty)
            );
        }
    }

    #[test]
    fn type_21_job_identity_has_mixed_proven_endianness() {
        // "123456789" is the CRC-16/XMODEM canonical KAT (0x31c3).
        assert_eq!(
            job_identity(&research_capability(), "123456789", 0x5678).as_bytes(),
            [
                0x43, 0x4e, 0x9e, 0xb2, 0x21, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x31, 0xc3,
                0x78, 0x56,
            ]
        );

        let key = JobIdentityKey::from_job_id("123456789", 0x5678);
        assert_eq!(key.job_id_crc(), 0x31c3);
        assert_eq!(key.pool_index(), 0x5678);
        assert!(JobIdentityCache::default().would_emit(key));
        assert!(
            conditional_job_identity(&research_capability(), JobIdentityCache::default(), key,)
                .is_some()
        );
        assert!(conditional_job_identity(
            &research_capability(),
            JobIdentityCache::after(key),
            key,
        )
        .is_none());

        // Stock's cache is zero-initialized, so the all-zero identity is also
        // suppressed on the first update rather than being treated specially.
        let zero = JobIdentityKey::from_job_id("", 0);
        assert_eq!(zero.combined(), 0);
        assert!(conditional_job_identity(
            &research_capability(),
            JobIdentityCache::default(),
            zero,
        )
        .is_none());
    }

    #[test]
    fn coinbase_fragment_boundaries_and_golden_frames_are_exact() {
        let coinbase: Vec<_> = (0u8..=129).collect();
        let frames = coinbase_fragments(&research_capability(), &coinbase).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].len(), MAX_FRAME_LEN);
        assert_eq!(frames[0].packet_type(), TYPE_COINBASE);
        assert_eq!(
            &frames[0].as_bytes()[..12],
            &[0x43, 0x4e, 0xfd, 0x29, 0x22, 0, 0, 0, 2, 0, 128, 0]
        );
        assert_eq!(
            &frames[0].as_bytes()[12..],
            &(0u8..=127).collect::<Vec<_>>()
        );
        assert_eq!(
            frames[1].as_bytes(),
            [0x43, 0x4e, 0x4d, 0x5c, 0x22, 0, 1, 0, 2, 0, 2, 0, 128, 129]
        );
    }

    #[test]
    fn fragment_builders_refuse_wraparound_and_empty_coinbase() {
        assert_eq!(
            coinbase_fragments(&research_capability(), &[]),
            Err(Nano3TxError::EmptyCoinbase)
        );
        let too_large = vec![0u8; COINBASE_FRAGMENT_LEN * (MAX_FRAGMENT_COUNT + 1)];
        assert!(matches!(
            coinbase_fragments(&research_capability(), &too_large),
            Err(Nano3TxError::TooManyFragments {
                kind: "coinbase",
                observed: 256,
                maximum: 255,
            })
        ));
        let too_many_merkle = vec![[0u8; MERKLE_BRANCH_LEN]; MAX_MERKLE_BRANCH_COUNT + 1];
        assert!(matches!(
            merkle_fragments(&research_capability(), &too_many_merkle),
            Err(Nano3TxError::TooManyMerkleBranches {
                observed: 31,
                maximum: 30,
            })
        ));
    }

    #[test]
    fn semantic_header_template_matches_cgminer_parse_notify_layout() {
        let template = StratumHeaderTemplate::from_wire_fields(
            [0x20, 0, 0, 0],
            [0x11; 32],
            [0x65, 0xaa, 0xbb, 0xcc],
            [0x1d, 0x00, 0xff, 0xff],
        );
        let bytes = template.as_bytes();
        assert_eq!(&bytes[0..4], &[0x20, 0, 0, 0]);
        assert_eq!(&bytes[4..36], &[0x11; 32]);
        assert_eq!(&bytes[36..68], &[0; 32]);
        assert_eq!(&bytes[68..72], &[0x65, 0xaa, 0xbb, 0xcc]);
        assert_eq!(&bytes[72..76], &[0x1d, 0x00, 0xff, 0xff]);
        assert_eq!(&bytes[76..80], &[0; 4]);
        assert_eq!(&bytes[80..128], &SHA256_WORK_PADDING);
        assert_eq!(bytes[83], 0x80);
        assert_eq!(&bytes[124..128], &[0x80, 0x02, 0, 0]);
    }

    #[test]
    fn merkle_and_work_24_chunks_match_literal_disassembly_vectors() {
        let branch: [u8; MERKLE_BRANCH_LEN] = core::array::from_fn(|i| i as u8);
        let merkle = merkle_fragments(&research_capability(), &[branch]).unwrap();
        assert_eq!(
            merkle[0].as_bytes(),
            [
                0x43, 0x4e, 0x9d, 0x69, 0x23, 0, 0, 0, 1, 0, 32, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                31,
            ]
        );

        let raw: [u8; WORK_24_BLOCK_LEN] = core::array::from_fn(|i| i as u8);
        let template = StratumHeaderTemplate(raw);
        let chunks = work_24_fragments(&research_capability(), &template);
        assert_eq!(chunks.len(), WORK_24_CHUNK_COUNT);
        assert_eq!(
            chunks[0].as_bytes(),
            [
                0x43, 0x4e, 0xe6, 0x4c, 0x24, 0, 0, 0, 4, 0, 32, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                31,
            ]
        );
        for (index, frame) in chunks.iter().enumerate() {
            assert_eq!(frame.as_bytes()[6..8], (index as u16).to_le_bytes());
            assert_eq!(frame.as_bytes()[8..10], 4u16.to_le_bytes());
            assert_eq!(
                &frame.as_bytes()[HEADER_LEN..],
                &raw[index * 32..(index + 1) * 32]
            );
        }
    }

    #[test]
    fn stock_job_trace_is_ordered_coherent_and_deduplicates_identity() {
        let coinbase: Vec<_> = (0u8..=129).collect();
        let branches = [[0x5a; MERKLE_BRANCH_LEN]];
        let header_template = StratumHeaderTemplate::from_wire_fields(
            [0x20, 0, 0, 0],
            [0x11; 32],
            [0x65, 0xaa, 0xbb, 0xcc],
            [0x1d, 0x00, 0xff, 0xff],
        );
        let input = StockJobTraceInput {
            parameters: JobParameters {
                coinbase_len: coinbase.len() as u32,
                nonce2_offset: 8,
                nonce2_size: 4,
                merkle_branch_count: branches.len() as u8,
                device_index: 0,
                total_devices: 1,
                restart: false,
            },
            versions: VersionRollingWords {
                micro_job_0: 0x2000_0000,
                micro_job_2: 0x2000_2000,
                micro_job_4: 0x2000_4000,
                micro_job_8: 0x2000_8000,
            },
            pool_difficulty: 1.0,
            job_id: "123456789",
            pool_index: 2,
            coinbase: &coinbase,
            merkle_branches: &branches,
            header_template: &header_template,
        };

        let first =
            stock_job_trace(&research_capability(), JobIdentityCache::default(), input).unwrap();
        assert!(first.emitted_identity());
        assert_eq!(
            first
                .frames()
                .iter()
                .map(Nano3TxFrame::packet_type)
                .collect::<Vec<_>>(),
            [
                TYPE_JOB_PARAMETERS,
                TYPE_VERSION_WORDS,
                TYPE_TARGET,
                TYPE_JOB_IDENTITY,
                TYPE_COINBASE,
                TYPE_COINBASE,
                TYPE_MERKLE,
                TYPE_WORK_24,
                TYPE_WORK_24,
                TYPE_WORK_24,
                TYPE_WORK_24,
                TYPE_JOB_FINISH,
            ]
        );

        let repeated =
            stock_job_trace(&research_capability(), first.next_identity_cache(), input).unwrap();
        assert!(!repeated.emitted_identity());
        assert_eq!(repeated.frames().len(), first.frames().len() - 1);
        assert!(!repeated
            .frames()
            .iter()
            .any(|frame| frame.packet_type() == TYPE_JOB_IDENTITY));
    }

    #[test]
    fn stock_job_trace_refuses_incoherent_declared_lengths() {
        let coinbase = [0u8; 64];
        let branches = [[0u8; MERKLE_BRANCH_LEN]];
        let header_template =
            StratumHeaderTemplate::from_wire_fields([0; 4], [0; 32], [0; 4], [0; 4]);
        let base = StockJobTraceInput {
            parameters: JobParameters {
                coinbase_len: 63,
                nonce2_offset: 8,
                nonce2_size: 4,
                merkle_branch_count: 1,
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
            job_id: "job",
            pool_index: 0,
            coinbase: &coinbase,
            merkle_branches: &branches,
            header_template: &header_template,
        };

        assert_eq!(
            stock_job_trace(&research_capability(), JobIdentityCache::default(), base),
            Err(Nano3TxError::CoinbaseLengthMismatch {
                declared: 63,
                observed: 64,
            })
        );
        assert_eq!(
            stock_job_trace(
                &research_capability(),
                JobIdentityCache::default(),
                StockJobTraceInput {
                    parameters: JobParameters {
                        coinbase_len: 64,
                        merkle_branch_count: 0,
                        ..base.parameters
                    },
                    ..base
                },
            ),
            Err(Nano3TxError::MerkleCountMismatch {
                declared: 0,
                observed: 1,
            })
        );
    }

    #[test]
    fn share_verifier_accepts_bitcoin_genesis_through_stock_reconstruction() {
        let coinbase_hash = double_sha256(&genesis_coinbase());
        assert_eq!(
            coinbase_hash,
            decode_hex("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a")
                .as_slice()
        );

        let (jobs, identity) = genesis_jobs(1.0, 4);
        let admitted = jobs
            .admit_nonce_candidate(genesis_nonce(identity), NANO3_ASIC_COUNT)
            .unwrap();
        let verified = verify_share_candidate(admitted).unwrap();

        let expected_header = decode_hex(concat!(
            "01000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            "29ab5f49",
            "ffff001d",
            "1dac2b7c",
        ));
        let expected_hash =
            decode_hex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000");
        assert_eq!(verified.header(), expected_header.as_slice());
        assert_eq!(verified.hash(), expected_hash.as_slice());
        assert_eq!(verified.record(), genesis_nonce(identity));
        assert_eq!(verified.job_generation(), identity.generation);
        assert_eq!(verified.history_slot(), 0);

        let mut diff_one_target = [0u8; 32];
        diff_one_target[26] = 0xff;
        diff_one_target[27] = 0xff;
        assert_eq!(verified.assigned_target(), &diff_one_target);
    }

    #[test]
    fn share_header_reconstruction_matches_independent_branch_and_roll_kat() {
        let coinbase: Vec<u8> = (0u8..64).collect();
        let branches = [core::array::from_fn(|index| 0xa0 + index as u8)];
        let header_template = StratumHeaderTemplate::from_wire_fields(
            0x2000_0000u32.to_be_bytes(),
            core::array::from_fn(|index| index as u8),
            0x6500_0000u32.to_be_bytes(),
            0x1d00_ffffu32.to_be_bytes(),
        );
        let snapshot = share_job_snapshot(
            &research_capability(),
            StockJobTraceInput {
                parameters: JobParameters {
                    coinbase_len: coinbase.len() as u32,
                    nonce2_offset: 8,
                    nonce2_size: 4,
                    merkle_branch_count: 1,
                    device_index: 0,
                    total_devices: 1,
                    restart: false,
                },
                versions: VersionRollingWords {
                    micro_job_0: 0x2000_0000,
                    micro_job_2: 0x2000_2000,
                    micro_job_4: 0x2000_4000,
                    micro_job_8: 0x2000_8000,
                },
                pool_difficulty: 1.0,
                job_id: "branch-kat",
                pool_index: 2,
                coinbase: &coinbase,
                merkle_branches: &branches,
                header_template: &header_template,
            },
        )
        .unwrap();
        let mut jobs = Nano3RecentJobs::new();
        let identity = jobs.remember("branch-kat", 2, snapshot).unwrap();
        let record = NonceRecord {
            job_id_crc: identity.job_id_crc,
            pool_index: identity.pool_index,
            nonce2: 0x1122_3344,
            nonce: 0xdead_beef,
            asic_id: 9,
            miner_id: 0,
            ntime_offset: 3,
            mid_id: 2,
            valid_marker: 1,
        };
        let admitted = jobs
            .admit_nonce_candidate(record, NANO3_ASIC_COUNT)
            .unwrap();
        let header = rebuild_share_header(&admitted.matched_job().job, admitted.record()).unwrap();

        // Independent Python hashlib KAT pins nonce2 LE insertion, one merkle
        // branch, mid-id 2 -> version word 4, ntime roll, and word flips.
        assert_eq!(
            header.as_slice(),
            decode_hex(concat!(
                "00400020",
                "03020100070605040b0a09080f0e0d0c13121110171615141b1a19181f1e1d1c",
                "41414c71d382f8a97888cf1116de731ba6f178ea6362cc76c2df57b64a5813f5",
                "03000065ffff001ddeadbeef",
            ))
            .as_slice()
        );
        assert_eq!(
            double_sha256(&header).as_slice(),
            decode_hex("d063fde3ec524bb40451c1f0489367e2144243b431f05b65e069c6c564089da7")
                .as_slice()
        );
    }

    #[test]
    fn share_verifier_uses_unclamped_pool_target_after_diff_one_prefilter() {
        let (jobs, identity) = genesis_jobs(1.0e12, 4);
        let admitted = jobs
            .admit_nonce_candidate(genesis_nonce(identity), NANO3_ASIC_COUNT)
            .unwrap();
        assert_eq!(
            verify_share_candidate(admitted),
            Err(Nano3ShareError::DoesNotMeetAssignedTarget)
        );

        assert_ne!(
            share_target_from_pool_difficulty(8192.0).unwrap(),
            target_from_pool_difficulty(8192.0).unwrap()
        );
    }

    #[test]
    fn share_verifier_refuses_nonce2_truncation_and_ntime_overflow() {
        let (jobs, identity) = genesis_jobs(1.0, 3);
        let mut oversized_nonce2 = genesis_nonce(identity);
        oversized_nonce2.nonce2 = NONCE2_SIZE_THREE_RANGE + 1;
        let admitted = jobs
            .admit_nonce_candidate(oversized_nonce2, NANO3_ASIC_COUNT)
            .unwrap();
        assert_eq!(
            verify_share_candidate(admitted),
            Err(Nano3ShareError::Nonce2DoesNotFit {
                value: NONCE2_SIZE_THREE_RANGE + 1,
                size: 3,
            })
        );

        let coinbase = genesis_coinbase();
        let header_template = StratumHeaderTemplate::from_wire_fields(
            1u32.to_be_bytes(),
            [0; 32],
            u32::MAX.to_be_bytes(),
            0x1d00_ffffu32.to_be_bytes(),
        );
        let snapshot = share_job_snapshot(
            &research_capability(),
            StockJobTraceInput {
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
                job_id: "ntime-overflow",
                pool_index: 0,
                coinbase: &coinbase,
                merkle_branches: &[],
                header_template: &header_template,
            },
        )
        .unwrap();
        let mut jobs = Nano3RecentJobs::new();
        let identity = jobs.remember("ntime-overflow", 0, snapshot).unwrap();
        let mut overflow = genesis_nonce(identity);
        overflow.ntime_offset = 1;
        let admitted = jobs
            .admit_nonce_candidate(overflow, NANO3_ASIC_COUNT)
            .unwrap();
        assert_eq!(
            verify_share_candidate(admitted),
            Err(Nano3ShareError::NtimeOverflow {
                base: u32::MAX,
                offset: 1,
            })
        );
    }

    #[test]
    fn finish_frames_are_exact_but_not_complete_contracts() {
        assert_eq!(
            job_finish(&research_capability()).as_bytes(),
            [0x43, 0x4e, 0x17, 0x8d, 0x26, 0, 0, 0, 1, 0, 0, 0]
        );
        assert_eq!(
            init_finish(&research_capability()).as_bytes(),
            [0x43, 0x4e, 0xbb, 0x77, 0x31, 0, 0, 0, 1, 0, 0, 0]
        );
        assert_eq!(
            require_complete_init_contract(),
            Err(Nano3TxError::CompleteInitContractUnresolved)
        );
        assert_eq!(
            require_complete_job_contract(),
            Err(Nano3TxError::CompleteJobContractUnresolved)
        );
    }

    #[test]
    fn native_transmit_authority_remains_fail_closed() {
        assert_eq!(
            require_native_tx_authority(),
            Err(Nano3TxError::NativeTxNotAuthorized)
        );
        assert!(!crate::nano3_profile::NANO3.native_tx_authorized());
        assert!(!crate::nano3_profile::NANO3.is_energizable());
    }
}
