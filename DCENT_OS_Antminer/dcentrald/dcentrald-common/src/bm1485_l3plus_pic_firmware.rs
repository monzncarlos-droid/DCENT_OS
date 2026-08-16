//! Exact held L3+ PIC application and dormant host-updater contracts.
//!
//! The application payload is copyable firmware evidence, not physical-board
//! identity. This module performs no I/O and grants no PIC, rail, install, or
//! recovery authority. Destructive updater symbols exist only in builds with
//! the `recovery-tool` feature.

pub const BM1485_L3PLUS_PIC_APPLICATION_PATH: &str = "/sbin/pic.txt";
pub const BM1485_L3PLUS_PIC_APPLICATION_SHA256: &str =
    "e93587e5c724ec568d4125ca49600848d0319eae865f7d4110242597c6e5fc8f";
pub const BM1485_L3PLUS_PIC_APPLICATION_BYTES: usize = 19_200;
pub const BM1485_L3PLUS_PIC_APPLICATION_IDENTICAL_HELD_COPIES: usize = 6;
pub const BM1485_L3PLUS_PIC_APPLICATION_WORDS: usize = 3_200;
pub const BM1485_L3PLUS_PIC_APPLICATION_LINE_BYTES: usize = 6;
pub const BM1485_L3PLUS_PIC_APPLICATION_START_WORD_ADDRESS: u16 = 0x0300;
pub const BM1485_L3PLUS_PIC_APPLICATION_END_WORD_ADDRESS: u16 = 0x0f7f;
pub const BM1485_L3PLUS_PIC_APPLICATION_ZERO_WORDS: usize = 48;
pub const BM1485_L3PLUS_PIC_APPLICATION_FIRST_WORDS: [u16; 10] = [
    0x3183, 0x2b15, 0x343d, 0x3400, 0x147e, 0x3183, 0x0020, 0x087f, 0x00ee, 0x0021,
];
pub const BM1485_L3PLUS_PIC_APPLICATION_LAST_WORDS: [u16; 5] =
    [0x0024, 0x01c0, 0x01c1, 0x2f0a, 0x3545];

/// The application initializes OPTION_REG to seven: internal TMR0 clock with
/// the prescaler assigned to TMR0 at 1:256. It does not initialize OSCCON.
pub const BM1485_L3PLUS_PIC_OPTION_REG: u8 = 0x07;
pub const BM1485_L3PLUS_PIC_TMR0_PRESCALER: u16 = 256;
pub const BM1485_L3PLUS_PIC_HEARTBEAT_TIMER_RELOAD: u16 = 61;
pub const BM1485_L3PLUS_PIC_HEARTBEAT_OUTER_CUT_THRESHOLD: u16 = 61;
pub const BM1485_L3PLUS_PIC_INITIAL_TIMEOUT_OVERFLOW_EVENTS: u32 = 3_844;
pub const BM1485_L3PLUS_PIC_POST_HEARTBEAT_TIMEOUT_OVERFLOW_EVENTS: u32 = 3_783;
pub const BM1485_L3PLUS_PIC_RA2_HIGH_MEANS_RAIL_DISABLED: bool = true;
/// Exact opcode-0x17 reply in the held application.
pub const BM1485_L3PLUS_PIC_FIRMWARE_VERSION_LITERAL: u8 = 3;
/// Data-NVM byte read into the DAC shadow during application startup.
pub const BM1485_L3PLUS_PIC_DAC_SHADOW_NVM_ADDRESS: u16 = 0x0fe0;
/// DACCON1 startup substitute when the stored shadow byte is erased (`0xff`).
/// The shadow itself remains `0xff` until opcode 0x10 changes it.
pub const BM1485_L3PLUS_PIC_ERASED_DAC_BOOT_FALLBACK: u8 = 0x7f;
pub const BM1485_L3PLUS_PIC_OPAQUE_TABLE_NVM_ADDRESS: u16 = 0x0fe1;
pub const BM1485_L3PLUS_PIC_OPAQUE_TABLE_VALUES: usize = 8;
pub const BM1485_L3PLUS_PIC_OPAQUE_TABLE_WORDS: usize = 4;
/// Bounded exact-app xref result: `0x0fe1` is recovered only in the opcode
/// 0x22 writer and opcode 0x23 reader, not an operational calculation path.
pub const BM1485_L3PLUS_PIC_HAS_RECOVERED_NONCOMMAND_OPAQUE_TABLE_CONSUMER: bool = false;
/// The exact held ARM host's recovered normal path has no opcode-0x10 call.
pub const BM1485_L3PLUS_HOST_NORMAL_PATH_MUTATES_PIC_DAC: bool = false;
pub const BM1485_L3PLUS_PIC_APPLICATION_ESTABLISHES_WALL_TIMEOUT: bool = false;
pub const BM1485_L3PLUS_PIC_FIRMWARE_IDENTIFIES_PHYSICAL_BOARD: bool = false;
pub const BM1485_L3PLUS_PIC_FIRMWARE_AUTHORIZES_CARRIER: bool = false;
pub const BM1485_L3PLUS_PIC_FIRMWARE_AUTHORIZES_RAIL_MUTATION: bool = false;
pub const BM1485_L3PLUS_PIC_FIRMWARE_AUTHORIZES_INSTALL: bool = false;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1485L3PlusPicFirmwareError {
    WrongLength {
        expected: usize,
        actual: usize,
    },
    InvalidLineTerminator {
        line: usize,
    },
    InvalidUppercaseHex {
        line: usize,
        column: usize,
        byte: u8,
    },
    WordOutsideFourteenBits {
        line: usize,
        value: u16,
    },
    Sha256Mismatch,
    PathMismatch,
    HeldCopyCountMismatch {
        expected: usize,
        actual: usize,
    },
    AnchorMismatch,
    ZeroWordCountMismatch {
        expected: usize,
        actual: usize,
    },
}

/// Parse the exact fixed-width `pic.txt` representation used by the held
/// updater: 3,200 uppercase four-hex-digit words, each followed by CRLF.
pub fn bm1485_l3plus_parse_pic_application(
    bytes: &[u8],
) -> Result<Box<[u16; BM1485_L3PLUS_PIC_APPLICATION_WORDS]>, Bm1485L3PlusPicFirmwareError> {
    if bytes.len() != BM1485_L3PLUS_PIC_APPLICATION_BYTES {
        return Err(Bm1485L3PlusPicFirmwareError::WrongLength {
            expected: BM1485_L3PLUS_PIC_APPLICATION_BYTES,
            actual: bytes.len(),
        });
    }

    let mut words = Box::new([0_u16; BM1485_L3PLUS_PIC_APPLICATION_WORDS]);
    for (line, (word, chunk)) in words
        .iter_mut()
        .zip(bytes.chunks_exact(BM1485_L3PLUS_PIC_APPLICATION_LINE_BYTES))
        .enumerate()
    {
        let &[hex0, hex1, hex2, hex3, carriage_return, line_feed] = chunk else {
            return Err(Bm1485L3PlusPicFirmwareError::WrongLength {
                expected: BM1485_L3PLUS_PIC_APPLICATION_LINE_BYTES,
                actual: chunk.len(),
            });
        };
        if carriage_return != b'\r' || line_feed != b'\n' {
            return Err(Bm1485L3PlusPicFirmwareError::InvalidLineTerminator { line });
        }

        let mut value = 0_u16;
        for (column, byte) in [hex0, hex1, hex2, hex3].into_iter().enumerate() {
            let nibble = match byte {
                b'0'..=b'9' => u16::from(byte - b'0'),
                b'A'..=b'F' => u16::from(byte - b'A' + 10),
                _ => {
                    return Err(Bm1485L3PlusPicFirmwareError::InvalidUppercaseHex {
                        line,
                        column,
                        byte,
                    });
                }
            };
            value = (value << 4) | nibble;
        }
        if value > 0x3fff {
            return Err(Bm1485L3PlusPicFirmwareError::WordOutsideFourteenBits { line, value });
        }
        *word = value;
    }
    Ok(words)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusPicFirmwareObservation<'a> {
    pub path: &'a str,
    pub sha256: &'a str,
    pub identical_held_copies: usize,
}

/// Passive, caller-supplied artifact consistency result. Its private fields
/// prevent it from being confused with an execution or physical-board token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusPicFirmwareAssessment {
    parsed_word_count: usize,
    zero_word_count: usize,
}

impl Bm1485L3PlusPicFirmwareAssessment {
    pub const fn parsed_word_count(self) -> usize {
        self.parsed_word_count
    }

    pub const fn zero_word_count(self) -> usize {
        self.zero_word_count
    }

    pub const fn is_caller_forgeable(self) -> bool {
        true
    }

    pub const fn authorizes_execution(self) -> bool {
        false
    }

    pub const fn authorizes_install(self) -> bool {
        false
    }
}

pub fn bm1485_l3plus_assess_pic_firmware(
    bytes: &[u8],
    observation: Bm1485L3PlusPicFirmwareObservation<'_>,
) -> Result<Bm1485L3PlusPicFirmwareAssessment, Bm1485L3PlusPicFirmwareError> {
    if observation.path != BM1485_L3PLUS_PIC_APPLICATION_PATH {
        return Err(Bm1485L3PlusPicFirmwareError::PathMismatch);
    }
    if observation.sha256 != BM1485_L3PLUS_PIC_APPLICATION_SHA256 {
        return Err(Bm1485L3PlusPicFirmwareError::Sha256Mismatch);
    }
    if observation.identical_held_copies != BM1485_L3PLUS_PIC_APPLICATION_IDENTICAL_HELD_COPIES {
        return Err(Bm1485L3PlusPicFirmwareError::HeldCopyCountMismatch {
            expected: BM1485_L3PLUS_PIC_APPLICATION_IDENTICAL_HELD_COPIES,
            actual: observation.identical_held_copies,
        });
    }

    let words = bm1485_l3plus_parse_pic_application(bytes)?;
    if !words.starts_with(&BM1485_L3PLUS_PIC_APPLICATION_FIRST_WORDS)
        || !words.ends_with(&BM1485_L3PLUS_PIC_APPLICATION_LAST_WORDS)
    {
        return Err(Bm1485L3PlusPicFirmwareError::AnchorMismatch);
    }
    let zero_word_count = words.iter().filter(|word| **word == 0).count();
    if zero_word_count != BM1485_L3PLUS_PIC_APPLICATION_ZERO_WORDS {
        return Err(Bm1485L3PlusPicFirmwareError::ZeroWordCountMismatch {
            expected: BM1485_L3PLUS_PIC_APPLICATION_ZERO_WORDS,
            actual: zero_word_count,
        });
    }

    Ok(Bm1485L3PlusPicFirmwareAssessment {
        parsed_word_count: words.len(),
        zero_word_count,
    })
}

/// Pure startup observation for the application DAC byte. This is a register
/// replay, not a voltage conversion, physical-load statement, or live token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusPicDacBootObservation {
    stored_shadow: u8,
    daccon1_written: u8,
}

impl Bm1485L3PlusPicDacBootObservation {
    /// Reproduce `FUN_CODE_0e82`: read data-NVM `0x0fe0`, retain that byte as
    /// the opcode-0x18 shadow, and substitute `0x7f` only for the initial
    /// DACCON1 write when the stored byte is erased (`0xff`).
    pub const fn from_stored_shadow(stored_shadow: u8) -> Self {
        Self {
            stored_shadow,
            daccon1_written: if stored_shadow == 0xff {
                BM1485_L3PLUS_PIC_ERASED_DAC_BOOT_FALLBACK
            } else {
                stored_shadow
            },
        }
    }

    pub const fn stored_shadow(self) -> u8 {
        self.stored_shadow
    }

    pub const fn daccon1_written(self) -> u8 {
        self.daccon1_written
    }

    pub const fn proves_voltage(self) -> bool {
        false
    }

    pub const fn authorizes_execution(self) -> bool {
        false
    }
}

/// Exact single-byte read replies recovered from the held application.
/// Unknown and multi-byte opcodes are intentionally outside this narrow API.
pub const fn bm1485_l3plus_pic_single_byte_read_reply(opcode: u8, dac_shadow: u8) -> Option<u8> {
    match opcode {
        0x17 => Some(BM1485_L3PLUS_PIC_FIRMWARE_VERSION_LITERAL),
        0x18 => Some(dac_shadow),
        _ => None,
    }
}

/// Decode the four persistent words returned by opcode 0x23. The first byte
/// of each pair is the stored high byte masked to six bits; the second is the
/// full low byte. The table's operational meaning is not established here.
pub const fn bm1485_l3plus_pic_decode_opaque_table(
    words: [u16; BM1485_L3PLUS_PIC_OPAQUE_TABLE_WORDS],
) -> [u8; BM1485_L3PLUS_PIC_OPAQUE_TABLE_VALUES] {
    let mut values = [0_u8; BM1485_L3PLUS_PIC_OPAQUE_TABLE_VALUES];
    let mut index = 0;
    while index < BM1485_L3PLUS_PIC_OPAQUE_TABLE_WORDS {
        values[index * 2] = ((words[index] >> 8) as u8) & 0x3f;
        values[index * 2 + 1] = words[index] as u8;
        index += 1;
    }
    values
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusPicTimer0Event {
    IgnoredWhileRailDisabled,
    CounterAdvanced,
    RailDisabledByHeartbeatTimeout,
}

/// Pure replay of the application-side heartbeat timer and RA2 rail-enable
/// state. RA2 high is disabled; command 0x15 with a nonzero payload drives it
/// low, while heartbeat command 0x16 resets counters but never re-enables it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusPicApplicationState {
    ra2_rail_disabled: bool,
    timer0_subcounter: u16,
    outer_counter: u16,
    heartbeat_seen: bool,
}

impl Bm1485L3PlusPicApplicationState {
    pub const fn initialized() -> Self {
        Self {
            ra2_rail_disabled: true,
            timer0_subcounter: BM1485_L3PLUS_PIC_HEARTBEAT_TIMER_RELOAD,
            outer_counter: 0,
            heartbeat_seen: false,
        }
    }

    pub const fn rail_is_disabled(self) -> bool {
        self.ra2_rail_disabled
    }

    pub const fn timer0_subcounter(self) -> u16 {
        self.timer0_subcounter
    }

    pub const fn outer_counter(self) -> u16 {
        self.outer_counter
    }

    pub const fn heartbeat_seen(self) -> bool {
        self.heartbeat_seen
    }

    pub const fn authorizes_execution(self) -> bool {
        false
    }

    /// Exact command-0x15 payload effect: zero drives RA2 high (disabled), and
    /// nonzero drives RA2 low (enabled). Counters are not reset.
    pub fn apply_rail_command_payload(&mut self, payload: u8) {
        self.ra2_rail_disabled = payload == 0;
    }

    /// Exact command-0x16 effect. A heartbeat does not drive RA2 low.
    pub fn apply_heartbeat(&mut self) {
        self.heartbeat_seen = true;
        self.timer0_subcounter = 0;
        self.outer_counter = 0;
    }

    pub fn observe_timer0_overflow(&mut self) -> Bm1485L3PlusPicTimer0Event {
        if self.ra2_rail_disabled {
            return Bm1485L3PlusPicTimer0Event::IgnoredWhileRailDisabled;
        }

        self.timer0_subcounter = self.timer0_subcounter.wrapping_sub(1);
        if self.timer0_subcounter != u16::MAX {
            return Bm1485L3PlusPicTimer0Event::CounterAdvanced;
        }

        self.timer0_subcounter = BM1485_L3PLUS_PIC_HEARTBEAT_TIMER_RELOAD;
        let previous_outer = self.outer_counter;
        self.outer_counter = self.outer_counter.wrapping_add(1);
        if previous_outer >= BM1485_L3PLUS_PIC_HEARTBEAT_OUTER_CUT_THRESHOLD {
            self.ra2_rail_disabled = true;
            self.outer_counter = 0;
            Bm1485L3PlusPicTimer0Event::RailDisabledByHeartbeatTimeout
        } else {
            Bm1485L3PlusPicTimer0Event::CounterAdvanced
        }
    }
}

impl Default for Bm1485L3PlusPicApplicationState {
    fn default() -> Self {
        Self::initialized()
    }
}

/// Destructive, latent application opcode. The exact held ARM normal path
/// does not call it, and default dcentrald builds do not link its planner.
#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_PIC_DAC_WRITE_OPCODE: u8 = 0x10;

/// Pure replay of application opcode 0x10. It describes PIC-side register and
/// data-NVM effects only; it supplies no transport or electrical authority.
#[cfg(feature = "recovery-tool")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusPicLatentDacWritePlan {
    payload: u8,
    previous_shadow: u8,
    persist_to_data_nvm: bool,
}

#[cfg(feature = "recovery-tool")]
impl Bm1485L3PlusPicLatentDacWritePlan {
    pub const fn payload(self) -> u8 {
        self.payload
    }

    /// Opcode 0x10 writes the payload directly to DACCON1 even if it equals
    /// the existing shadow and no persistent write follows.
    pub const fn daccon1_written(self) -> u8 {
        self.payload
    }

    pub const fn echoed_reply(self) -> u8 {
        self.payload
    }

    pub const fn previous_shadow(self) -> u8 {
        self.previous_shadow
    }

    pub const fn shadow_after(self) -> u8 {
        self.payload
    }

    pub const fn persists_to_data_nvm(self) -> bool {
        self.persist_to_data_nvm
    }

    pub const fn data_nvm_address(self) -> Option<u16> {
        if self.persist_to_data_nvm {
            Some(BM1485_L3PLUS_PIC_DAC_SHADOW_NVM_ADDRESS)
        } else {
            None
        }
    }

    /// The dispatcher calls the NVM helper and advances its shadow without
    /// checking a returned write status.
    pub const fn checks_persistence_write_result(self) -> bool {
        false
    }

    pub const fn reads_persistence_back(self) -> bool {
        false
    }

    pub const fn proves_voltage(self) -> bool {
        false
    }

    pub const fn authorizes_execution(self) -> bool {
        false
    }
}

#[cfg(feature = "recovery-tool")]
pub const fn bm1485_l3plus_pic_latent_dac_write_plan(
    previous_shadow: u8,
    payload: u8,
) -> Bm1485L3PlusPicLatentDacWritePlan {
    Bm1485L3PlusPicLatentDacWritePlan {
        payload,
        previous_shadow,
        persist_to_data_nvm: payload != previous_shadow,
    }
}

#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_PIC_OPAQUE_TABLE_WRITE_OPCODE: u8 = 0x22;
#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_PIC_OPAQUE_TABLE_READ_OPCODE: u8 = 0x23;

#[cfg(feature = "recovery-tool")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusPicOpaqueTableError {
    EvenValueOutsideSixBits { index: usize, value: u8 },
}

/// Recovery-only representation of the latent opcode-0x22 persistent write.
/// Rejecting lossy even-position values is independent fail-closed hardening;
/// stock silently masks those bytes with `0x3f`.
#[cfg(feature = "recovery-tool")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1485L3PlusPicOpaqueTableWritePlan {
    encoded_words: [u16; BM1485_L3PLUS_PIC_OPAQUE_TABLE_WORDS],
}

#[cfg(feature = "recovery-tool")]
impl Bm1485L3PlusPicOpaqueTableWritePlan {
    pub const fn encoded_words(self) -> [u16; BM1485_L3PLUS_PIC_OPAQUE_TABLE_WORDS] {
        self.encoded_words
    }

    pub const fn data_nvm_address(self) -> u16 {
        BM1485_L3PLUS_PIC_OPAQUE_TABLE_NVM_ADDRESS
    }

    pub const fn checks_persistence_write_result(self) -> bool {
        false
    }

    pub const fn reads_persistence_back(self) -> bool {
        false
    }

    pub const fn authorizes_execution(self) -> bool {
        false
    }
}

#[cfg(feature = "recovery-tool")]
pub const fn bm1485_l3plus_pic_opaque_table_write_plan(
    values: [u8; BM1485_L3PLUS_PIC_OPAQUE_TABLE_VALUES],
) -> Result<Bm1485L3PlusPicOpaqueTableWritePlan, Bm1485L3PlusPicOpaqueTableError> {
    let mut encoded_words = [0_u16; BM1485_L3PLUS_PIC_OPAQUE_TABLE_WORDS];
    let mut index = 0;
    while index < BM1485_L3PLUS_PIC_OPAQUE_TABLE_WORDS {
        let even_index = index * 2;
        let high = values[even_index];
        if high > 0x3f {
            return Err(Bm1485L3PlusPicOpaqueTableError::EvenValueOutsideSixBits {
                index: even_index,
                value: high,
            });
        }
        encoded_words[index] = ((high as u16) << 8) | values[even_index + 1] as u16;
        index += 1;
    }
    Ok(Bm1485L3PlusPicOpaqueTableWritePlan { encoded_words })
}

#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_PIC_FLASH_SET_POINTER_OPCODE: u8 = 0x01;
#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_PIC_FLASH_CACHE_OPCODE: u8 = 0x02;
#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_PIC_FLASH_ERASE_OPCODE: u8 = 0x04;
#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_PIC_FLASH_COMMIT_OPCODE: u8 = 0x05;
#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_PIC_FLASH_RESET_OPCODE: u8 = 0x07;
#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_PIC_FLASH_ERASE_ROWS: usize = 100;
#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_PIC_FLASH_WORDS_PER_ROW: usize = 32;
#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_PIC_FLASH_WORDS_PER_CACHE: usize = 8;
#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_PIC_FLASH_CACHE_BLOCKS: usize = 400;
#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_PIC_FLASH_TOTAL_COMMANDS: usize = 903;
#[cfg(feature = "recovery-tool")]
pub const BM1485_L3PLUS_PIC_FLASH_TOTAL_EXPLICIT_DWELL_MS: u32 = 250_600;

#[cfg(feature = "recovery-tool")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusPicRecoveryStepKind {
    ResetApplication,
    SetFlashPointer,
    EraseRow { row: u8 },
    CacheWords { block: u16 },
    CommitWords { block: u16 },
}

#[cfg(feature = "recovery-tool")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1485L3PlusPicRecoveryStep {
    pub kind: Bm1485L3PlusPicRecoveryStepKind,
    pub wire_bytes: Vec<u8>,
    pub dwell_after_ms: u32,
}

#[cfg(feature = "recovery-tool")]
impl Bm1485L3PlusPicRecoveryStep {
    pub const fn reads_response(&self) -> bool {
        false
    }

    pub const fn verifies_flash(&self) -> bool {
        false
    }

    pub const fn authorizes_execution(&self) -> bool {
        false
    }
}

#[cfg(feature = "recovery-tool")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1485L3PlusPicRecoveryError {
    StepIndexOutOfRange(usize),
    WordOutsideFourteenBits { word_index: usize, value: u16 },
}

/// Reconstruct one command in the exact dormant host updater. The updater
/// emits no readback, verify, or final jump-to-application command.
#[cfg(feature = "recovery-tool")]
pub fn bm1485_l3plus_pic_recovery_step(
    step_index: usize,
    words: &[u16; BM1485_L3PLUS_PIC_APPLICATION_WORDS],
) -> Result<Bm1485L3PlusPicRecoveryStep, Bm1485L3PlusPicRecoveryError> {
    if let Some((word_index, value)) = words
        .iter()
        .copied()
        .enumerate()
        .find(|(_, value)| *value > 0x3fff)
    {
        return Err(Bm1485L3PlusPicRecoveryError::WordOutsideFourteenBits { word_index, value });
    }
    let step = match step_index {
        0 => Bm1485L3PlusPicRecoveryStep {
            kind: Bm1485L3PlusPicRecoveryStepKind::ResetApplication,
            wire_bytes: vec![0x55, 0xaa, BM1485_L3PLUS_PIC_FLASH_RESET_OPCODE],
            dwell_after_ms: 600,
        },
        1 | 102 => Bm1485L3PlusPicRecoveryStep {
            kind: Bm1485L3PlusPicRecoveryStepKind::SetFlashPointer,
            wire_bytes: vec![
                0x55,
                0xaa,
                BM1485_L3PLUS_PIC_FLASH_SET_POINTER_OPCODE,
                0x03,
                0x00,
            ],
            dwell_after_ms: 0,
        },
        2..=101 => {
            let Ok(row) = u8::try_from(step_index - 2) else {
                return Err(Bm1485L3PlusPicRecoveryError::StepIndexOutOfRange(
                    step_index,
                ));
            };
            Bm1485L3PlusPicRecoveryStep {
                kind: Bm1485L3PlusPicRecoveryStepKind::EraseRow { row },
                wire_bytes: vec![0x55, 0xaa, BM1485_L3PLUS_PIC_FLASH_ERASE_OPCODE],
                dwell_after_ms: 500,
            }
        }
        103..BM1485_L3PLUS_PIC_FLASH_TOTAL_COMMANDS => {
            let relative = step_index - 103;
            let block = relative / 2;
            let Ok(block_u16) = u16::try_from(block) else {
                return Err(Bm1485L3PlusPicRecoveryError::StepIndexOutOfRange(
                    step_index,
                ));
            };
            if relative.is_multiple_of(2) {
                let Some(cache_words) = words
                    .chunks_exact(BM1485_L3PLUS_PIC_FLASH_WORDS_PER_CACHE)
                    .nth(block)
                else {
                    return Err(Bm1485L3PlusPicRecoveryError::StepIndexOutOfRange(
                        step_index,
                    ));
                };
                let mut wire_bytes = Vec::with_capacity(19);
                wire_bytes.extend_from_slice(&[0x55, 0xaa, BM1485_L3PLUS_PIC_FLASH_CACHE_OPCODE]);
                for word in cache_words {
                    wire_bytes.extend_from_slice(&word.to_be_bytes());
                }
                Bm1485L3PlusPicRecoveryStep {
                    kind: Bm1485L3PlusPicRecoveryStepKind::CacheWords { block: block_u16 },
                    wire_bytes,
                    dwell_after_ms: 0,
                }
            } else {
                Bm1485L3PlusPicRecoveryStep {
                    kind: Bm1485L3PlusPicRecoveryStepKind::CommitWords { block: block_u16 },
                    wire_bytes: vec![0x55, 0xaa, BM1485_L3PLUS_PIC_FLASH_COMMIT_OPCODE],
                    dwell_after_ms: 500,
                }
            }
        }
        _ => {
            return Err(Bm1485L3PlusPicRecoveryError::StepIndexOutOfRange(
                step_index,
            ));
        }
    };
    Ok(step)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_words() -> [u16; BM1485_L3PLUS_PIC_APPLICATION_WORDS] {
        let mut words = [1_u16; BM1485_L3PLUS_PIC_APPLICATION_WORDS];
        words[..BM1485_L3PLUS_PIC_APPLICATION_FIRST_WORDS.len()]
            .copy_from_slice(&BM1485_L3PLUS_PIC_APPLICATION_FIRST_WORDS);
        let tail =
            BM1485_L3PLUS_PIC_APPLICATION_WORDS - BM1485_L3PLUS_PIC_APPLICATION_LAST_WORDS.len();
        words[tail..].copy_from_slice(&BM1485_L3PLUS_PIC_APPLICATION_LAST_WORDS);
        let mut zeros_needed = BM1485_L3PLUS_PIC_APPLICATION_ZERO_WORDS;
        for word in &mut words[20..] {
            if zeros_needed == 0 {
                break;
            }
            *word = 0;
            zeros_needed -= 1;
        }
        words
    }

    fn encode_fixture(words: &[u16; BM1485_L3PLUS_PIC_APPLICATION_WORDS]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(BM1485_L3PLUS_PIC_APPLICATION_BYTES);
        for word in words {
            bytes.extend_from_slice(format!("{word:04X}\r\n").as_bytes());
        }
        bytes
    }

    #[test]
    fn exact_fixed_width_payload_parses_and_assesses_without_authority() {
        let bytes = encode_fixture(&fixture_words());
        let assessment = bm1485_l3plus_assess_pic_firmware(
            &bytes,
            Bm1485L3PlusPicFirmwareObservation {
                path: BM1485_L3PLUS_PIC_APPLICATION_PATH,
                sha256: BM1485_L3PLUS_PIC_APPLICATION_SHA256,
                identical_held_copies: BM1485_L3PLUS_PIC_APPLICATION_IDENTICAL_HELD_COPIES,
            },
        )
        .unwrap();
        assert_eq!(assessment.parsed_word_count(), 3_200);
        assert_eq!(assessment.zero_word_count(), 48);
        assert!(assessment.is_caller_forgeable());
        assert!(!assessment.authorizes_execution());
        assert!(!assessment.authorizes_install());
    }

    #[test]
    fn parser_refuses_length_case_crlf_and_fourteen_bit_violations() {
        let words = fixture_words();
        let bytes = encode_fixture(&words);
        assert!(matches!(
            bm1485_l3plus_parse_pic_application(&bytes[..bytes.len() - 1]),
            Err(Bm1485L3PlusPicFirmwareError::WrongLength { .. })
        ));

        let mut lowercase = bytes.clone();
        lowercase[0] = b'a';
        assert!(matches!(
            bm1485_l3plus_parse_pic_application(&lowercase),
            Err(Bm1485L3PlusPicFirmwareError::InvalidUppercaseHex { .. })
        ));

        let mut bad_crlf = bytes.clone();
        bad_crlf[4] = b'\n';
        assert!(matches!(
            bm1485_l3plus_parse_pic_application(&bad_crlf),
            Err(Bm1485L3PlusPicFirmwareError::InvalidLineTerminator { .. })
        ));

        let mut too_wide = bytes;
        too_wide[..4].copy_from_slice(b"4000");
        assert!(matches!(
            bm1485_l3plus_parse_pic_application(&too_wide),
            Err(Bm1485L3PlusPicFirmwareError::WordOutsideFourteenBits { .. })
        ));
    }

    #[test]
    fn artifact_tuple_and_anchors_are_fail_closed() {
        let mut bytes = encode_fixture(&fixture_words());
        let wrong_tuple = bm1485_l3plus_assess_pic_firmware(
            &bytes,
            Bm1485L3PlusPicFirmwareObservation {
                path: BM1485_L3PLUS_PIC_APPLICATION_PATH,
                sha256: BM1485_L3PLUS_PIC_APPLICATION_SHA256,
                identical_held_copies: 5,
            },
        );
        assert!(matches!(
            wrong_tuple,
            Err(Bm1485L3PlusPicFirmwareError::HeldCopyCountMismatch { .. })
        ));
        bytes[..4].copy_from_slice(b"0001");
        assert_eq!(
            bm1485_l3plus_assess_pic_firmware(
                &bytes,
                Bm1485L3PlusPicFirmwareObservation {
                    path: BM1485_L3PLUS_PIC_APPLICATION_PATH,
                    sha256: BM1485_L3PLUS_PIC_APPLICATION_SHA256,
                    identical_held_copies: 6,
                },
            ),
            Err(Bm1485L3PlusPicFirmwareError::AnchorMismatch)
        );
    }

    #[test]
    fn rail_command_is_active_low_and_heartbeat_does_not_reenable() {
        let mut state = Bm1485L3PlusPicApplicationState::initialized();
        assert!(state.rail_is_disabled());
        state.apply_rail_command_payload(1);
        assert!(!state.rail_is_disabled());
        state.apply_rail_command_payload(0);
        assert!(state.rail_is_disabled());
        state.apply_heartbeat();
        assert!(state.rail_is_disabled());
        assert!(state.heartbeat_seen());
        assert_eq!(state.timer0_subcounter(), 0);
        assert_eq!(state.outer_counter(), 0);
    }

    #[test]
    fn initial_enabled_timeout_occurs_on_exact_overflow_boundary() {
        let mut state = Bm1485L3PlusPicApplicationState::initialized();
        state.apply_rail_command_payload(1);
        for _ in 1..BM1485_L3PLUS_PIC_INITIAL_TIMEOUT_OVERFLOW_EVENTS {
            assert_ne!(
                state.observe_timer0_overflow(),
                Bm1485L3PlusPicTimer0Event::RailDisabledByHeartbeatTimeout
            );
        }
        assert!(!state.rail_is_disabled());
        assert_eq!(
            state.observe_timer0_overflow(),
            Bm1485L3PlusPicTimer0Event::RailDisabledByHeartbeatTimeout
        );
        assert!(state.rail_is_disabled());
    }

    #[test]
    fn post_heartbeat_timeout_occurs_on_exact_overflow_boundary() {
        let mut state = Bm1485L3PlusPicApplicationState::initialized();
        state.apply_rail_command_payload(1);
        state.apply_heartbeat();
        for _ in 1..BM1485_L3PLUS_PIC_POST_HEARTBEAT_TIMEOUT_OVERFLOW_EVENTS {
            assert_ne!(
                state.observe_timer0_overflow(),
                Bm1485L3PlusPicTimer0Event::RailDisabledByHeartbeatTimeout
            );
        }
        assert_eq!(
            state.observe_timer0_overflow(),
            Bm1485L3PlusPicTimer0Event::RailDisabledByHeartbeatTimeout
        );
    }

    #[test]
    fn disabled_state_freezes_timeout_counters() {
        let mut state = Bm1485L3PlusPicApplicationState::initialized();
        let before = state;
        assert_eq!(
            state.observe_timer0_overflow(),
            Bm1485L3PlusPicTimer0Event::IgnoredWhileRailDisabled
        );
        assert_eq!(state, before);
        assert!(!state.authorizes_execution());
        assert!(!BM1485_L3PLUS_PIC_APPLICATION_ESTABLISHES_WALL_TIMEOUT);
        assert!(!BM1485_L3PLUS_PIC_FIRMWARE_IDENTIFIES_PHYSICAL_BOARD);
        assert!(!BM1485_L3PLUS_PIC_FIRMWARE_AUTHORIZES_CARRIER);
        assert!(!BM1485_L3PLUS_PIC_FIRMWARE_AUTHORIZES_RAIL_MUTATION);
        assert!(!BM1485_L3PLUS_PIC_FIRMWARE_AUTHORIZES_INSTALL);
    }

    #[test]
    fn boot_dac_shadow_and_erased_fallback_are_distinct_and_non_authoritative() {
        let erased = Bm1485L3PlusPicDacBootObservation::from_stored_shadow(0xff);
        assert_eq!(erased.stored_shadow(), 0xff);
        assert_eq!(erased.daccon1_written(), 0x7f);
        assert_eq!(
            bm1485_l3plus_pic_single_byte_read_reply(0x18, erased.stored_shadow()),
            Some(0xff)
        );
        assert!(!erased.proves_voltage());
        assert!(!erased.authorizes_execution());

        for stored in 0_u8..=0xfe {
            let observation = Bm1485L3PlusPicDacBootObservation::from_stored_shadow(stored);
            assert_eq!(observation.stored_shadow(), stored);
            assert_eq!(observation.daccon1_written(), stored);
        }
    }

    #[test]
    fn exact_single_byte_read_replies_are_version_three_and_current_shadow() {
        assert_eq!(
            bm1485_l3plus_pic_single_byte_read_reply(0x17, 0xa5),
            Some(3)
        );
        assert_eq!(
            bm1485_l3plus_pic_single_byte_read_reply(0x18, 0xa5),
            Some(0xa5)
        );
        assert_eq!(bm1485_l3plus_pic_single_byte_read_reply(0x16, 0xa5), None);
        assert!(!BM1485_L3PLUS_HOST_NORMAL_PATH_MUTATES_PIC_DAC);
    }

    #[test]
    fn opaque_table_read_decodes_high_six_and_full_low_bytes_only() {
        assert_eq!(
            bm1485_l3plus_pic_decode_opaque_table([0xffff, 0x3f80, 0x1200, 0x00fe]),
            [0x3f, 0xff, 0x3f, 0x80, 0x12, 0x00, 0x00, 0xfe]
        );
        assert!(!BM1485_L3PLUS_PIC_HAS_RECOVERED_NONCOMMAND_OPAQUE_TABLE_CONSUMER);
    }

    #[cfg(feature = "recovery-tool")]
    #[test]
    fn latent_dac_write_always_updates_register_but_persists_only_on_change() {
        let unchanged = bm1485_l3plus_pic_latent_dac_write_plan(0x55, 0x55);
        assert_eq!(unchanged.payload(), 0x55);
        assert_eq!(unchanged.previous_shadow(), 0x55);
        assert_eq!(unchanged.daccon1_written(), 0x55);
        assert_eq!(unchanged.echoed_reply(), 0x55);
        assert_eq!(unchanged.shadow_after(), 0x55);
        assert!(!unchanged.persists_to_data_nvm());
        assert_eq!(unchanged.data_nvm_address(), None);

        let changed = bm1485_l3plus_pic_latent_dac_write_plan(0xff, 0x00);
        assert_eq!(changed.daccon1_written(), 0x00);
        assert_eq!(changed.echoed_reply(), 0x00);
        assert_eq!(changed.shadow_after(), 0x00);
        assert!(changed.persists_to_data_nvm());
        assert_eq!(changed.data_nvm_address(), Some(0x0fe0));
        assert!(!changed.checks_persistence_write_result());
        assert!(!changed.reads_persistence_back());
        assert!(!changed.proves_voltage());
        assert!(!changed.authorizes_execution());
    }

    #[cfg(feature = "recovery-tool")]
    #[test]
    fn opaque_table_write_packs_pairs_and_refuses_stock_silent_truncation() {
        let values = [0x00, 0xff, 0x01, 0x80, 0x3e, 0x00, 0x3f, 0xfe];
        let plan = bm1485_l3plus_pic_opaque_table_write_plan(values).unwrap();
        assert_eq!(plan.encoded_words(), [0x00ff, 0x0180, 0x3e00, 0x3ffe]);
        assert_eq!(plan.data_nvm_address(), 0x0fe1);
        assert_eq!(
            bm1485_l3plus_pic_decode_opaque_table(plan.encoded_words()),
            values
        );
        assert!(!plan.checks_persistence_write_result());
        assert!(!plan.reads_persistence_back());
        assert!(!plan.authorizes_execution());

        assert_eq!(
            bm1485_l3plus_pic_opaque_table_write_plan([0x40, 0, 0, 0, 0, 0, 0, 0]),
            Err(Bm1485L3PlusPicOpaqueTableError::EvenValueOutsideSixBits {
                index: 0,
                value: 0x40
            })
        );
    }

    #[cfg(feature = "recovery-tool")]
    #[test]
    fn recovery_plan_has_exact_command_count_boundaries_and_byte_order() {
        let words = fixture_words();
        let reset = bm1485_l3plus_pic_recovery_step(0, &words).unwrap();
        assert_eq!(reset.wire_bytes, [0x55, 0xaa, 0x07]);
        assert_eq!(reset.dwell_after_ms, 600);
        let pointer = bm1485_l3plus_pic_recovery_step(1, &words).unwrap();
        assert_eq!(pointer.wire_bytes, [0x55, 0xaa, 0x01, 0x03, 0x00]);
        let first_cache = bm1485_l3plus_pic_recovery_step(103, &words).unwrap();
        assert_eq!(
            &first_cache.wire_bytes[..5],
            &[0x55, 0xaa, 0x02, 0x31, 0x83]
        );
        assert_eq!(first_cache.wire_bytes.len(), 19);
        let last_commit = bm1485_l3plus_pic_recovery_step(902, &words).unwrap();
        assert_eq!(
            last_commit.kind,
            Bm1485L3PlusPicRecoveryStepKind::CommitWords { block: 399 }
        );
        assert_eq!(last_commit.wire_bytes, [0x55, 0xaa, 0x05]);
        assert!(matches!(
            bm1485_l3plus_pic_recovery_step(903, &words),
            Err(Bm1485L3PlusPicRecoveryError::StepIndexOutOfRange(903))
        ));
    }

    #[cfg(feature = "recovery-tool")]
    #[test]
    fn recovery_plan_pins_rows_dwell_and_absence_of_verify_or_jump() {
        let words = fixture_words();
        let mut dwell = 0_u32;
        let mut erases = 0;
        let mut caches = 0;
        let mut commits = 0;
        for step_index in 0..BM1485_L3PLUS_PIC_FLASH_TOTAL_COMMANDS {
            let step = bm1485_l3plus_pic_recovery_step(step_index, &words).unwrap();
            dwell += step.dwell_after_ms;
            erases += usize::from(matches!(
                step.kind,
                Bm1485L3PlusPicRecoveryStepKind::EraseRow { .. }
            ));
            caches += usize::from(matches!(
                step.kind,
                Bm1485L3PlusPicRecoveryStepKind::CacheWords { .. }
            ));
            commits += usize::from(matches!(
                step.kind,
                Bm1485L3PlusPicRecoveryStepKind::CommitWords { .. }
            ));
            assert!(!step.reads_response());
            assert!(!step.verifies_flash());
            assert!(!step.authorizes_execution());
            assert_ne!(step.wire_bytes.get(2), Some(&0x06));
        }
        assert_eq!(erases, BM1485_L3PLUS_PIC_FLASH_ERASE_ROWS);
        assert_eq!(caches, BM1485_L3PLUS_PIC_FLASH_CACHE_BLOCKS);
        assert_eq!(commits, BM1485_L3PLUS_PIC_FLASH_CACHE_BLOCKS);
        assert_eq!(dwell, BM1485_L3PLUS_PIC_FLASH_TOTAL_EXPLICIT_DWELL_MS);
        assert_eq!(
            BM1485_L3PLUS_PIC_FLASH_ERASE_ROWS * BM1485_L3PLUS_PIC_FLASH_WORDS_PER_ROW,
            BM1485_L3PLUS_PIC_APPLICATION_WORDS
        );

        let mut malformed = words;
        malformed[BM1485_L3PLUS_PIC_APPLICATION_WORDS - 1] = 0x4000;
        assert!(matches!(
            bm1485_l3plus_pic_recovery_step(0, &malformed),
            Err(Bm1485L3PlusPicRecoveryError::WordOutsideFourteenBits {
                word_index: 3_199,
                value: 0x4000
            })
        ));
    }
}
