// SPDX-License-Identifier: GPL-3.0-or-later
//
// 268-byte mm_pkg - Avalon Linux-internal cg_miner<->mm_miner IPC packet.
//
// Wire format (little-endian on K230 RV64):
//
//   offset  size  field
//   0       2     u16  type     — primary opcode, optionally carrying a subtype
//                                 in the unused byte (see `TypeWord`)
//   2       2     u16  idx      — index in fragmented multi-packet jobs
//   4       2     u16  num      — total fragments in current message
//   6       2     pad            - natural C alignment before uint32_t
//   8       4     u32  len       - total logical payload bytes across fragments
//   12      256   u8[] payload   - opcode-specific fragment payload
//                                 (always exactly 256 bytes on the wire even when
//                                 `len` < 256 — readers ignore tail bytes)
//
// Total = 268 bytes. Both Avalon_Nano3s (home) and Avalon_mm (industrial) use
// the IDENTICAL packet shape per `AVALON_NANO3S_REPO_MAP.md` §5 and
// `AVALON_MM_K230_INDUSTRIAL_RE.md` §3 — so the same codec serves both lines.
// The 12-byte header geometry and idx/num/len fragmentation are confirmed
// correct on both sides against the held 3S binaries.
//
// SUBTYPE LOCATION (corrected 2026-08-23): the subtype rides in the u16 type
// word, NOT in payload[0]. Commands from cg_miner carry
// `type = (primary << 8) | subtype` (fan = 0x3102, PLL = 0x3301, softoff =
// 0x3207); status replies from mm_miner are decoded by cg_miner as
// `primary = type & 0xFF; minor = type >> 8` (STATUS_ASIC|TEMP = 0x0454).
// Evidence: held `mm_miner` `decode_pkg` @0x3e0de (reads hdr.type u16;
// `hi = type>>8`; `hi != 0` → primary = hi, subtype = type & 0xFF; range
// check 0x10..0x33; jump table @0x12e4c8) and public `driver-avalon.c`
// (lines 100/815/1952/1969 + 571–573) proving both directions. Full working
// notes: `DCENT_OS_AvalonMiner/build/nano3-native-re/notes/
// nano3s-cross-reference.md` §4.1. The composition differs by direction, so
// every encode/decode is direction-aware.
//
// SysV msgq mtype convention (from `cg_miner/mm_miner.h`):
//   mtype = 0x1  — host (Linux, cg_miner) → ASIC daemon (mm_miner)
//   mtype = 0x2  — ASIC daemon → host
//
// The transport layer prepends mtype as a `c_long` per `msgsnd(2)` ABI; this
// module's encode/decode operates on the 268-byte packet body only.

use core::convert::TryFrom;

/// Total wire size of an mm_pkg in bytes.
pub const MM_PKG_SIZE: usize = 268;

/// Header byte count (preceding the 256-byte payload).
pub const MM_PKG_HEADER_SIZE: usize = 12;

/// Fixed payload byte count.
pub const MM_PKG_PAYLOAD_SIZE: usize = 256;

/// Direction of an mm_pkg on the SysV message queue.
///
/// The type-word composition rule is asymmetric: commands place the primary
/// in the high byte, replies place it in the low byte. Direction is therefore
/// required to encode or decode a subtype-carrying packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// mtype 0x1 — cg_miner → mm_miner command. Compound type word is
    /// `(primary << 8) | subtype`.
    HostToMm,
    /// mtype 0x2 — mm_miner → cg_miner reply. Compound type word is
    /// `(subtype << 8) | primary`.
    MmToHost,
}

#[derive(Debug, thiserror::Error)]
pub enum MmPkgError {
    #[error("buffer too small: expected {MM_PKG_SIZE} bytes, got {0}")]
    ShortBuffer(usize),

    #[error("single-packet payload length {len} exceeds {MM_PKG_PAYLOAD_SIZE}")]
    LenOverflow { len: u32 },

    #[error("logical message length {len} cannot be represented by u32/u16 fragments")]
    MessageTooLarge { len: usize },

    #[error("invalid fragment metadata: idx={idx}, num={num}, len={len}")]
    InvalidFragment { idx: u16, num: u16, len: u32 },

    #[error("fragment set is inconsistent or incomplete")]
    InvalidFragmentSet,

    #[error("unknown opcode 0x{0:02X}")]
    UnknownOpcode(u16),

    #[error("subtype 0x{0:02X} is only valid on subtype-carrying primaries")]
    SubtypeOnSimpleOpcode(u8),
}

/// Avalon mm_pkg primary opcode space.
///
/// Primary values from :73-91`
/// (BSD-2 file), cross-checked against the held 3S `mm_miner` dispatch jump
/// table @0x12e4c8 (primaries 0x10, 0x20, 0x30–0x33, plus raw 0x61; anything
/// else is a no-op in that build):
///
///   - `0x10..=0x1F` — handshake recognition
///   - `0x20..=0x2F` — pivotal poll
///   - `0x30..=0x33` — set commands (host → MM controller); these three carry
///     a subtype in the type word — see `SetPeriphSubtype`/`SetSysSubtype`/
///     `SetAsicSubtype`
///   - `0x50..=0x5F` — status replies (MM → host); `StatusAsic` carries a
///     subtype in the type word — see `StatusAsicSubtype`
///   - `0x60..`      — admin (pools, reboot)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Opcode {
    /// `AVA_P_DETECT` — controller discovery / handshake (host → MM).
    Detect = 0x10,
    /// `AVA_P_ACKDETECT` — detect acknowledgement (MM → host).
    AckDetect = 0x11,
    /// `AVA_P_POLLING` — pivotal poll (host → MM).
    Polling = 0x20,
    /// `AVA_P_SET_JOB` — submit mining job (host → MM, may fragment via idx/num).
    SetJob = 0x30,
    /// `AVA_P_SET_PERIPH` — peripheral config; subtype required
    /// (volt/fan/audio/lcd/net/led/...).
    SetPeriph = 0x31,
    /// `AVA_P_SET_SYS` — system config; subtype required
    /// (target temp / mode / reboot / ...).
    SetSys = 0x32,
    /// `AVA_P_SET_ASIC` — ASIC config; subtype required
    /// (PLL / SS / SSDN_PRO / PLL_SEL).
    SetAsic = 0x33,
    /// `AVA_P_STATUS_NONCE` — nonce result (MM → host). Payload is a `MinerNonce`.
    StatusNonce = 0x50,
    /// `AVA_P_STATUS_PERIPH` — peripheral status reply.
    StatusPeriph = 0x51,
    /// `AVA_P_STATUS_SYS` — system status reply.
    StatusSys = 0x52,
    /// `AVA_P_STATUS_MINER` — miner-level telemetry reply (`miner_info`).
    StatusMiner = 0x53,
    /// `AVA_P_STATUS_ASIC` — per-ASIC status reply; subtype in the type word
    /// (PLL/temp/volt/efuse/...).
    StatusAsic = 0x54,
    /// `AVA_P_SET_POOLS` — pool configuration.
    SetPools = 0x60,
    /// `AVA_P_WEB_REBOOT` — admin reboot command (`am_system_reboot(2,0)`).
    WebReboot = 0x61,
}

impl Opcode {
    /// Whether this primary carries a subtype in the compound type word.
    pub const fn carries_subtype(self) -> bool {
        matches!(
            self,
            Opcode::SetPeriph | Opcode::SetSys | Opcode::SetAsic | Opcode::StatusAsic
        )
    }
}

impl TryFrom<u16> for Opcode {
    type Error = MmPkgError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x10 => Opcode::Detect,
            0x11 => Opcode::AckDetect,
            0x20 => Opcode::Polling,
            0x30 => Opcode::SetJob,
            0x31 => Opcode::SetPeriph,
            0x32 => Opcode::SetSys,
            0x33 => Opcode::SetAsic,
            0x50 => Opcode::StatusNonce,
            0x51 => Opcode::StatusPeriph,
            0x52 => Opcode::StatusSys,
            0x53 => Opcode::StatusMiner,
            0x54 => Opcode::StatusAsic,
            0x60 => Opcode::SetPools,
            0x61 => Opcode::WebReboot,
            other => return Err(MmPkgError::UnknownOpcode(other)),
        })
    }
}

/// Subtype of `AVA_P_SET_PERIPH` (compound type `0x31SS`).
///
/// Held-binary `mmu_set_periph` jump table; payload carries the subtype's own
/// data starting at `payload[0]` (e.g. FAN: int percent, 15–100 or −1 = auto).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SetPeriphSubtype {
    Volt = 0x01,
    /// Fan speed percent (int payload; 15–100, or −1 for auto/PID).
    Fan = 0x02,
    Audio = 0x04,
    Lcd = 0x05,
    Net0 = 0x06,
    Net1 = 0x07,
    Net2 = 0x08,
    LightSense = 0x09,
    LedMode = 0x10,
    LedDay = 0x11,
    NightLamp = 0x12,
    HashSn = 0x13,
}

/// Subtype of `AVA_P_SET_SYS` (compound type `0x32SS`).
///
/// Held-binary `mmu_set_sys` jump table @0x12e360. Note `SoftOn`/`SoftOff`
/// are LOG-ONLY NO-OPS in mmu_set_sys on the 3S — the real softoff is local
/// to mm_miner (`power_onoff(0)` rail cut). They are modeled here because
/// they appear on the wire, not because they act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SetSysSubtype {
    /// payload[0] → target temperature global.
    TargetTemp = 0x01,
    VoltTuning = 0x02,
    /// Work level; persisted via `syscfg_workinfo_set`.
    Level = 0x03,
    /// Work mode byte; persisted.
    Mode = 0x04,
    /// payload u16 delay seconds; 0 → immediate `am_system_reboot(3,0)`.
    Reboot = 0x05,
    /// Log-only no-op in mmu_set_sys (real soft-on is local).
    SoftOn = 0x06,
    /// Log-only no-op in mmu_set_sys (real soft-off is local).
    SoftOff = 0x07,
    AgingParameter = 0x08,
    FilterClean = 0x09,
    TimeZone = 0x10,
    /// payload u64 unix timestamp.
    Timestamp = 0x11,
    WebPass = 0x12,
    EnvTemp = 0x13,
    /// payload[0]=level, payload[1]=mode; persisted.
    ModeLevel = 0x14,
    HwInfo = 0x15,
    Activation = 0x16,
}

/// Subtype of `AVA_P_SET_ASIC` (compound type `0x33SS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SetAsicSubtype {
    /// PLL / frequency control (20-byte `asic_pll_setting`).
    Pll = 0x01,
    /// SS — soft-start / spread spectrum.
    Ss = 0x02,
    /// SSDN_PRO — power-saving down ramp.
    SsdnPro = 0x03,
    /// PLL_SEL — PLL selection / divider (8-byte).
    PllSel = 0x04,
}

/// Subtype of `AVA_P_STATUS_ASIC` replies (compound type `0xSS54`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatusAsicSubtype {
    PllCnt = 0x00,
    Pll = 0x01,
    PassCore = 0x02,
    FailCore = 0x03,
    /// Die-temperature telemetry (source of the STATUS_ASIC|TEMP 0x0454 reply).
    Temp = 0x04,
    Volt = 0x05,
    EFuse = 0x06,
    Max = 0x07,
}

/// A parsed or composed u16 type word: primary opcode plus optional subtype.
///
/// Composition is direction-dependent (see [`Direction`]):
/// commands `(primary << 8) | subtype`, replies `(subtype << 8) | primary`.
/// A subtype is only accepted on subtype-carrying primaries
/// (SET_PERIPH/SET_SYS/SET_ASIC/STATUS_ASIC); the held binary dispatches
/// subtypes only for those handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeWord {
    pub primary: Opcode,
    pub subtype: Option<u8>,
    pub direction: Direction,
}

impl TypeWord {
    /// Parse a raw wire type word in the given direction.
    ///
    /// Command parsing mirrors the held `mm_miner` `decode_pkg`: `hi != 0` →
    /// primary = hi, subtype = low byte; `hi == 0` → simple primary. Reply
    /// parsing mirrors cg_miner: primary = low byte, subtype = high byte
    /// (0 = none). Unknown subtypes decode as raw bytes; unknown primaries
    /// are an error.
    pub fn from_raw(raw: u16, direction: Direction) -> Result<Self, MmPkgError> {
        let (primary_raw, subtype) = match direction {
            Direction::HostToMm => {
                let hi = raw >> 8;
                if hi == 0 {
                    (raw, None)
                } else {
                    (hi, Some((raw & 0xFF) as u8))
                }
            }
            Direction::MmToHost => {
                let lo = raw & 0xFF;
                let hi = raw >> 8;
                (lo, if hi == 0 { None } else { Some(hi as u8) })
            }
        };
        let primary = Opcode::try_from(primary_raw)?;
        if let Some(sub) = subtype {
            if !primary.carries_subtype() {
                return Err(MmPkgError::SubtypeOnSimpleOpcode(sub));
            }
        }
        Ok(Self {
            primary,
            subtype,
            direction,
        })
    }

    /// Compose the raw wire type word.
    pub fn to_raw(self) -> u16 {
        match (self.direction, self.subtype) {
            (Direction::HostToMm, Some(sub)) => ((self.primary as u16) << 8) | sub as u16,
            (Direction::HostToMm, None) => self.primary as u16,
            (Direction::MmToHost, Some(sub)) => ((sub as u16) << 8) | self.primary as u16,
            (Direction::MmToHost, None) => self.primary as u16,
        }
    }
}

/// 12-byte naturally aligned C `mm_header`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmPkgHeader {
    pub type_word: TypeWord,
    /// Fragment index when a logical message spans multiple packets (0-based).
    pub idx: u16,
    /// Total fragments in the current logical message.
    pub num: u16,
    /// Total logical payload byte count across all fragments.
    pub len: u32,
}

/// Full 268-byte mm_pkg.
#[derive(Debug, Clone)]
pub struct MmPkg {
    pub header: MmPkgHeader,
    pub payload: [u8; MM_PKG_PAYLOAD_SIZE],
}

impl MmPkg {
    /// Build an mm_pkg with the given type word and payload slice.
    /// The slice is copied into the 256-byte payload buffer; remaining bytes are zeroed.
    /// Returns an error if `payload.len() > 256`.
    pub fn new(type_word: TypeWord, payload_bytes: &[u8]) -> Result<Self, MmPkgError> {
        if payload_bytes.len() > MM_PKG_PAYLOAD_SIZE {
            return Err(MmPkgError::LenOverflow {
                len: payload_bytes.len() as u32,
            });
        }
        let mut payload = [0u8; MM_PKG_PAYLOAD_SIZE];
        payload[..payload_bytes.len()].copy_from_slice(payload_bytes);
        Ok(Self {
            header: MmPkgHeader {
                type_word,
                idx: 0,
                num: 1,
                len: payload_bytes.len() as u32,
            },
            payload,
        })
    }

    /// Convenience constructor for a simple (subtype-free) opcode.
    pub fn simple(
        opcode: Opcode,
        direction: Direction,
        payload_bytes: &[u8],
    ) -> Result<Self, MmPkgError> {
        Self::new(
            TypeWord {
                primary: opcode,
                subtype: None,
                direction,
            },
            payload_bytes,
        )
    }

    /// Convenience constructor for a subtype-carrying opcode.
    pub fn compound(
        opcode: Opcode,
        subtype: u8,
        direction: Direction,
        payload_bytes: &[u8],
    ) -> Result<Self, MmPkgError> {
        Self::new(
            TypeWord {
                primary: opcode,
                subtype: Some(subtype),
                direction,
            },
            payload_bytes,
        )
    }

    /// Split one logical payload into ABI-correct 256-byte fragments.
    ///
    /// Every fragment carries the same type word, total `len` and `num`;
    /// `idx` is zero-based. This matches Canaan's un-packed C struct and
    /// fragment loop.
    pub fn fragment(type_word: TypeWord, payload_bytes: &[u8]) -> Result<Vec<Self>, MmPkgError> {
        let total_len =
            u32::try_from(payload_bytes.len()).map_err(|_| MmPkgError::MessageTooLarge {
                len: payload_bytes.len(),
            })?;
        let num = expected_fragment_count(total_len).ok_or(MmPkgError::MessageTooLarge {
            len: payload_bytes.len(),
        })?;

        if payload_bytes.is_empty() {
            return Self::new(type_word, &[]).map(|pkg| vec![pkg]);
        }

        payload_bytes
            .chunks(MM_PKG_PAYLOAD_SIZE)
            .enumerate()
            .map(|(idx, chunk)| {
                let mut payload = [0u8; MM_PKG_PAYLOAD_SIZE];
                payload[..chunk.len()].copy_from_slice(chunk);
                Ok(Self {
                    header: MmPkgHeader {
                        type_word,
                        idx: idx as u16,
                        num,
                        len: total_len,
                    },
                    payload,
                })
            })
            .collect()
    }

    /// Reassemble a complete, consistently described fragment set.
    pub fn reassemble(fragments: &[Self]) -> Result<Vec<u8>, MmPkgError> {
        let first = fragments.first().ok_or(MmPkgError::InvalidFragmentSet)?;
        validate_fragment(first.header.idx, first.header.num, first.header.len)?;
        if fragments.len() != first.header.num as usize {
            return Err(MmPkgError::InvalidFragmentSet);
        }

        let mut seen = vec![false; first.header.num as usize];
        let mut out = vec![0u8; first.header.len as usize];
        for fragment in fragments {
            validate_fragment(
                fragment.header.idx,
                fragment.header.num,
                fragment.header.len,
            )?;
            if fragment.header.type_word != first.header.type_word
                || fragment.header.num != first.header.num
                || fragment.header.len != first.header.len
                || seen[fragment.header.idx as usize]
            {
                return Err(MmPkgError::InvalidFragmentSet);
            }
            seen[fragment.header.idx as usize] = true;
            let start = fragment.header.idx as usize * MM_PKG_PAYLOAD_SIZE;
            let valid = fragment.payload_valid();
            out[start..start + valid.len()].copy_from_slice(valid);
        }
        if seen.iter().any(|present| !present) {
            return Err(MmPkgError::InvalidFragmentSet);
        }
        Ok(out)
    }

    /// Decode an mm_pkg from a byte slice in the given direction.
    /// Slice must be at least 268 bytes.
    pub fn decode(buf: &[u8], direction: Direction) -> Result<Self, MmPkgError> {
        if buf.len() < MM_PKG_SIZE {
            return Err(MmPkgError::ShortBuffer(buf.len()));
        }
        let type_raw = u16::from_le_bytes([buf[0], buf[1]]);
        let idx = u16::from_le_bytes([buf[2], buf[3]]);
        let num = u16::from_le_bytes([buf[4], buf[5]]);
        let len = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let type_word = TypeWord::from_raw(type_raw, direction)?;
        validate_fragment(idx, num, len)?;
        let mut payload = [0u8; MM_PKG_PAYLOAD_SIZE];
        payload.copy_from_slice(&buf[MM_PKG_HEADER_SIZE..MM_PKG_SIZE]);
        Ok(Self {
            header: MmPkgHeader {
                type_word,
                idx,
                num,
                len,
            },
            payload,
        })
    }

    /// Encode this mm_pkg into a 268-byte array.
    pub fn encode(&self) -> [u8; MM_PKG_SIZE] {
        let mut out = [0u8; MM_PKG_SIZE];
        out[0..2].copy_from_slice(&self.header.type_word.to_raw().to_le_bytes());
        out[2..4].copy_from_slice(&self.header.idx.to_le_bytes());
        out[4..6].copy_from_slice(&self.header.num.to_le_bytes());
        // out[6..8] intentionally remains zero: it is C struct padding.
        out[8..12].copy_from_slice(&self.header.len.to_le_bytes());
        out[MM_PKG_HEADER_SIZE..MM_PKG_SIZE].copy_from_slice(&self.payload);
        out
    }

    /// Return this fragment's valid payload prefix.
    pub fn payload_valid(&self) -> &[u8] {
        let start = self.header.idx as usize * MM_PKG_PAYLOAD_SIZE;
        let len = (self.header.len as usize)
            .saturating_sub(start)
            .min(MM_PKG_PAYLOAD_SIZE);
        &self.payload[..len]
    }
}

fn expected_fragment_count(len: u32) -> Option<u16> {
    let count = if len == 0 {
        1
    } else {
        u64::from(len).div_ceil(MM_PKG_PAYLOAD_SIZE as u64)
    };
    u16::try_from(count).ok()
}

fn validate_fragment(idx: u16, num: u16, len: u32) -> Result<(), MmPkgError> {
    let expected = expected_fragment_count(len);
    if expected != Some(num) || idx >= num {
        return Err(MmPkgError::InvalidFragment { idx, num, len });
    }
    Ok(())
}

/// Decoded payload of an `AVA_P_STATUS_NONCE` (0x50) packet.
///
/// Verbatim translation of `struct miner_nonce` from
/// :233-243` (BSD-2 file):
///
/// ```c
/// struct miner_nonce {
///     volatile uint32_t job_id           : 32;   // word 0
///     volatile uint32_t nonce2           : 32;   // word 1
///     volatile uint32_t nonce            : 32;   // word 2
///     volatile uint32_t asic_id          : 10;   // word 3, bits  0..9
///     volatile uint32_t miner_id         :  6;   // word 3, bits 10..15
///     volatile uint32_t ntime            :  8;   // word 3, bits 16..23
///     volatile uint32_t mid_id           :  4;   // word 3, bits 24..27 (ASICBoost slot)
///     volatile uint32_t valid            :  4;   // word 3, bits 28..31
///     volatile uint32_t last_job_nonce2  : 32;   // word 4
/// };
/// ```
///
/// Total = 5 × 32-bit = 20 bytes on the wire. C bit-fields on Linux/RISC-V GCC
/// are LSB-first within each 32-bit word, little-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MinerNonce {
    pub job_id: u32,
    pub nonce2: u32,
    pub nonce: u32,
    /// 10-bit ASIC index in [0..1024).
    pub asic_id: u16,
    /// 6-bit miner index in [0..64).
    pub miner_id: u8,
    /// 8-bit ntime offset.
    pub ntime: u8,
    /// 4-bit ASICBoost midstate slot.
    pub mid_id: u8,
    /// 4-bit validity flag.
    pub valid: u8,
    pub last_job_nonce2: u32,
}

/// Wire size of a `MinerNonce` payload.
pub const MINER_NONCE_SIZE: usize = 20;

impl MinerNonce {
    /// Decode a `MinerNonce` from the first 20 bytes of an `AVA_P_STATUS_NONCE`
    /// packet's payload. Trailing bytes (up to the 256-byte payload size) are
    /// ignored. Returns `None` if the slice is shorter than 20 bytes.
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() < MINER_NONCE_SIZE {
            return None;
        }
        let job_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let nonce2 = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let nonce = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let packed = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let last_job_nonce2 =
            u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
        Some(Self {
            job_id,
            nonce2,
            nonce,
            // Bit layout: LSB-first within the u32 word.
            asic_id: (packed & 0x3FF) as u16,
            miner_id: ((packed >> 10) & 0x3F) as u8,
            ntime: ((packed >> 16) & 0xFF) as u8,
            mid_id: ((packed >> 24) & 0x0F) as u8,
            valid: ((packed >> 28) & 0x0F) as u8,
            last_job_nonce2,
        })
    }

    /// Encode back to a 20-byte payload (test helper / future packet builders).
    pub fn encode(&self) -> [u8; MINER_NONCE_SIZE] {
        let mut out = [0u8; MINER_NONCE_SIZE];
        out[0..4].copy_from_slice(&self.job_id.to_le_bytes());
        out[4..8].copy_from_slice(&self.nonce2.to_le_bytes());
        out[8..12].copy_from_slice(&self.nonce.to_le_bytes());
        let packed: u32 = (self.asic_id as u32 & 0x3FF)
            | ((self.miner_id as u32 & 0x3F) << 10)
            | ((self.ntime as u32 & 0xFF) << 16)
            | ((self.mid_id as u32 & 0x0F) << 24)
            | ((self.valid as u32 & 0x0F) << 28);
        out[12..16].copy_from_slice(&packed.to_le_bytes());
        out[16..20].copy_from_slice(&self.last_job_nonce2.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMD: Direction = Direction::HostToMm;
    const RPL: Direction = Direction::MmToHost;

    #[test]
    fn round_trip_detect() {
        let pkg = MmPkg::simple(Opcode::Detect, CMD, b"hello").unwrap();
        let wire = pkg.encode();
        assert_eq!(wire.len(), MM_PKG_SIZE);
        let decoded = MmPkg::decode(&wire, CMD).unwrap();
        assert_eq!(decoded.header.type_word.primary, Opcode::Detect);
        assert_eq!(decoded.header.type_word.subtype, None);
        assert_eq!(decoded.header.len, 5);
        assert_eq!(decoded.payload_valid(), b"hello");
    }

    #[test]
    fn detect_empty_packet_matches_literal_wire_header() {
        let wire = MmPkg::simple(Opcode::Detect, CMD, &[]).unwrap().encode();

        assert_eq!(wire.len(), MM_PKG_SIZE);
        assert_eq!(
            &wire[..18],
            &[
                0x10, 0x00, // type Detect
                0x00, 0x00, // idx
                0x01, 0x00, // num
                0x00, 0x00, // natural C padding
                0x00, 0x00, 0x00, 0x00, // len
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // payload prefix
            ]
        );
        assert!(wire[MM_PKG_HEADER_SIZE..].iter().all(|b| *b == 0));
    }

    // --- subtype-in-type-word correction (held-binary evidence) ---

    #[test]
    fn command_fan_sets_compound_type_word_0x3102() {
        // SET_PERIPH|FAN command = 0x3102, little-endian bytes 02 31.
        let pkg = MmPkg::compound(
            Opcode::SetPeriph,
            SetPeriphSubtype::Fan as u8,
            CMD,
            &40i32.to_le_bytes(),
        )
        .unwrap();
        let wire = pkg.encode();
        assert_eq!(&wire[..2], &[0x02, 0x31]);

        let decoded = MmPkg::decode(&wire, CMD).unwrap();
        assert_eq!(decoded.header.type_word.primary, Opcode::SetPeriph);
        assert_eq!(
            decoded.header.type_word.subtype,
            Some(SetPeriphSubtype::Fan as u8)
        );
        assert_eq!(&decoded.payload_valid()[..4], &40i32.to_le_bytes());
    }

    #[test]
    fn command_pll_sets_compound_type_word_0x3301() {
        let wire = MmPkg::compound(Opcode::SetAsic, SetAsicSubtype::Pll as u8, CMD, &[0xAA; 20])
            .unwrap()
            .encode();
        assert_eq!(&wire[..2], &[0x01, 0x33]);
        let decoded = MmPkg::decode(&wire, CMD).unwrap();
        assert_eq!(decoded.header.type_word.primary, Opcode::SetAsic);
        assert_eq!(
            decoded.header.type_word.subtype,
            Some(SetAsicSubtype::Pll as u8)
        );
    }

    #[test]
    fn command_softoff_sets_compound_type_word_0x3207() {
        // SET_SYS|SOFTOFF = 0x3207 — a real wire command even though mmu_set_sys
        // treats it as a log-only no-op on the 3S.
        let wire = MmPkg::compound(Opcode::SetSys, SetSysSubtype::SoftOff as u8, CMD, &[1])
            .unwrap()
            .encode();
        assert_eq!(&wire[..2], &[0x07, 0x32]);
        assert_eq!(
            MmPkg::decode(&wire, CMD).unwrap().header.type_word.subtype,
            Some(0x07)
        );
    }

    #[test]
    fn reply_status_asic_temp_composes_subtype_high_0x0454() {
        // STATUS_ASIC|TEMP reply = 0x0454 (subtype 0x04 high, primary 0x54 low).
        let pkg = MmPkg::compound(
            Opcode::StatusAsic,
            StatusAsicSubtype::Temp as u8,
            RPL,
            &[0x55; 8],
        )
        .unwrap();
        let wire = pkg.encode();
        assert_eq!(&wire[..2], &[0x54, 0x04]);

        let decoded = MmPkg::decode(&wire, RPL).unwrap();
        assert_eq!(decoded.header.type_word.primary, Opcode::StatusAsic);
        assert_eq!(
            decoded.header.type_word.subtype,
            Some(StatusAsicSubtype::Temp as u8)
        );
    }

    #[test]
    fn reply_direction_is_required_to_read_compound_words() {
        // 0x0454 read as a command would mean primary 0x04 — not a known
        // opcode — proving the two directions cannot share one parser.
        let mut wire = [0u8; MM_PKG_SIZE];
        wire[0..2].copy_from_slice(&0x0454u16.to_le_bytes());
        wire[4] = 0x01;
        assert!(matches!(
            MmPkg::decode(&wire, CMD).unwrap_err(),
            MmPkgError::UnknownOpcode(0x04)
        ));
    }

    #[test]
    fn subtype_on_simple_opcode_rejected() {
        // Compound SET_JOB (0x30SS) never appears on the wire; refuse it.
        let mut wire = [0u8; MM_PKG_SIZE];
        wire[0..2].copy_from_slice(&0x3001u16.to_le_bytes());
        wire[4] = 0x01;
        assert!(matches!(
            MmPkg::decode(&wire, CMD).unwrap_err(),
            MmPkgError::SubtypeOnSimpleOpcode(0x01)
        ));
    }

    #[test]
    fn set_job_packet_pins_len_prefix_and_zero_padding() {
        let wire = MmPkg::simple(Opcode::SetJob, CMD, &[0xDE, 0xAD, 0xBE, 0xEF])
            .unwrap()
            .encode();

        assert_eq!(
            &wire[..20],
            &[
                0x30, 0x00, // type SetJob
                0x00, 0x00, // idx
                0x01, 0x00, // num
                0x00, 0x00, // natural C padding
                0x04, 0x00, 0x00, 0x00, // len
                0xDE, 0xAD, 0xBE, 0xEF, // valid payload
                0x00, 0x00, 0x00, 0x00, // padding starts immediately after len
            ]
        );
        assert!(wire[MM_PKG_HEADER_SIZE + 4..].iter().all(|b| *b == 0));
    }

    #[test]
    fn rejects_short_buffer() {
        let buf = [0u8; 100];
        let err = MmPkg::decode(&buf, CMD).unwrap_err();
        assert!(matches!(err, MmPkgError::ShortBuffer(100)));
    }

    #[test]
    fn rejects_unknown_opcode() {
        // 0xFFFF as a command parses as primary 0xFF (high byte) with subtype
        // 0xFF; the unknown *primary* is what fails.
        let mut wire = [0u8; MM_PKG_SIZE];
        wire[0] = 0xFF;
        wire[1] = 0xFF;
        let err = MmPkg::decode(&wire, CMD).unwrap_err();
        assert!(matches!(err, MmPkgError::UnknownOpcode(0xFF)));

        // A unknown simple primary still reports the raw low byte.
        let mut simple = [0u8; MM_PKG_SIZE];
        simple[0] = 0x0F;
        simple[4] = 0x01;
        assert!(matches!(
            MmPkg::decode(&simple, CMD).unwrap_err(),
            MmPkgError::UnknownOpcode(0x0F)
        ));
    }

    #[test]
    fn accepts_total_len_larger_than_one_fragment() {
        let mut wire = [0u8; MM_PKG_SIZE];
        wire[0] = 0x10; // Detect
        wire[2..4].copy_from_slice(&2u16.to_le_bytes());
        wire[4..6].copy_from_slice(&4u16.to_le_bytes());
        wire[8..12].copy_from_slice(&999u32.to_le_bytes());
        let decoded = MmPkg::decode(&wire, CMD).unwrap();
        assert_eq!(decoded.header.len, 999);
        assert_eq!(decoded.payload_valid().len(), 256);
    }

    #[test]
    fn rejects_inconsistent_fragment_metadata() {
        let mut wire = [0u8; MM_PKG_SIZE];
        wire[0] = 0x10;
        wire[2..4].copy_from_slice(&2u16.to_le_bytes());
        wire[4..6].copy_from_slice(&1u16.to_le_bytes());
        wire[8..12].copy_from_slice(&10u32.to_le_bytes());
        let err = MmPkg::decode(&wire, CMD).unwrap_err();
        assert!(matches!(err, MmPkgError::InvalidFragment { .. }));
    }

    #[test]
    fn payload_oversize_rejected_at_construction() {
        let big = vec![0u8; 300];
        let err = MmPkg::simple(Opcode::SetJob, CMD, &big).unwrap_err();
        assert!(matches!(err, MmPkgError::LenOverflow { .. }));
    }

    #[test]
    fn fragments_and_reassembles_multi_packet_payload() {
        let original: Vec<u8> = (0..700).map(|index| (index % 251) as u8).collect();
        let fragments = MmPkg::fragment(
            TypeWord {
                primary: Opcode::SetJob,
                subtype: None,
                direction: CMD,
            },
            &original,
        )
        .unwrap();
        assert_eq!(fragments.len(), 3);
        assert_eq!(
            fragments[0].header,
            MmPkgHeader {
                type_word: TypeWord {
                    primary: Opcode::SetJob,
                    subtype: None,
                    direction: CMD,
                },
                idx: 0,
                num: 3,
                len: 700,
            }
        );
        assert_eq!(fragments[0].payload_valid().len(), 256);
        assert_eq!(fragments[1].payload_valid().len(), 256);
        assert_eq!(fragments[2].payload_valid().len(), 188);

        let reordered = [
            fragments[2].clone(),
            fragments[0].clone(),
            fragments[1].clone(),
        ];
        assert_eq!(MmPkg::reassemble(&reordered).unwrap(), original);
    }

    #[test]
    fn round_trip_set_job() {
        // Confirm the renamed-and-renumbered SetJob opcode (0x30, was Work=0x24)
        // round-trips correctly. This is the host→MM mining-job carrier.
        let pkg = MmPkg::simple(Opcode::SetJob, CMD, &[1, 2, 3, 4]).unwrap();
        let wire = pkg.encode();
        // Verify the type byte ordering on the wire matches mm_miner.h:
        // header.type is little-endian u16; SetJob = 0x0030.
        assert_eq!(wire[0], 0x30);
        assert_eq!(wire[1], 0x00);
        let decoded = MmPkg::decode(&wire, CMD).unwrap();
        assert_eq!(decoded.header.type_word.primary, Opcode::SetJob);
        assert_eq!(decoded.header.len, 4);
        assert_eq!(decoded.payload_valid(), &[1, 2, 3, 4]);
    }

    #[test]
    fn status_nonce_opcode_decodes() {
        // StatusNonce was incorrectly placed at 0x42 in the original draft;
        // verify it decodes from the actual wire value 0x50.
        let mut wire = [0u8; MM_PKG_SIZE];
        wire[0] = 0x50;
        wire[4] = 0x01;
        let pkg = MmPkg::decode(&wire, RPL).unwrap();
        assert_eq!(pkg.header.type_word.primary, Opcode::StatusNonce);
    }

    #[test]
    fn ack_detect_opcode_decodes() {
        let mut wire = [0u8; MM_PKG_SIZE];
        wire[0] = 0x11;
        wire[4] = 0x01;
        let pkg = MmPkg::decode(&wire, RPL).unwrap();
        assert_eq!(pkg.header.type_word.primary, Opcode::AckDetect);
    }

    #[test]
    fn miner_nonce_round_trip() {
        let nonce = MinerNonce {
            job_id: 0x1234_5678,
            nonce2: 0x9ABC_DEF0,
            nonce: 0xDEAD_BEEF,
            asic_id: 0x1FF, // 10 bits — max-ish
            miner_id: 0x2A, // 6 bits
            ntime: 0xA5,    // 8 bits
            mid_id: 0x07,   // 4 bits
            valid: 0x0E,    // 4 bits
            last_job_nonce2: 0xCAFE_F00D,
        };
        let wire = nonce.encode();
        assert_eq!(wire.len(), MINER_NONCE_SIZE);
        let decoded = MinerNonce::decode(&wire).expect("20-byte slice should decode");
        assert_eq!(decoded, nonce);
    }

    #[test]
    fn miner_nonce_matches_literal_bitfield_golden() {
        let nonce = MinerNonce {
            job_id: 0x1234_5678,
            nonce2: 0x9ABC_DEF0,
            nonce: 0xDEAD_BEEF,
            asic_id: 0x1FF,
            miner_id: 0x2A,
            ntime: 0xA5,
            mid_id: 0x07,
            valid: 0x0E,
            last_job_nonce2: 0xCAFE_F00D,
        };

        let wire = nonce.encode();
        assert_eq!(
            wire,
            [
                0x78, 0x56, 0x34, 0x12, 0xF0, 0xDE, 0xBC, 0x9A, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xA9,
                0xA5, 0xE7, 0x0D, 0xF0, 0xFE, 0xCA,
            ]
        );
        assert_eq!(MinerNonce::decode(&wire), Some(nonce));
    }

    #[test]
    fn miner_nonce_rejects_short_slice() {
        let buf = [0u8; 10];
        assert!(MinerNonce::decode(&buf).is_none());
    }

    #[test]
    fn miner_nonce_decodes_from_full_payload() {
        // The 256-byte payload of a real STATUS_NONCE packet starts with 20 B of
        // miner_nonce; trailing bytes are padding/noise that decode() must ignore.
        let mut payload = [0u8; MM_PKG_PAYLOAD_SIZE];
        payload[0..4].copy_from_slice(&42u32.to_le_bytes());
        payload[12..16].copy_from_slice(&((0x123u32) | (0x05 << 10) | (0x80 << 16)).to_le_bytes());
        let n = MinerNonce::decode(&payload).unwrap();
        assert_eq!(n.job_id, 42);
        assert_eq!(n.asic_id, 0x123);
        assert_eq!(n.miner_id, 0x05);
        assert_eq!(n.ntime, 0x80);
    }

    fn sample_status_nonce() -> MinerNonce {
        MinerNonce {
            job_id: 0x1234_5678,
            nonce2: 0x9ABC_DEF0,
            nonce: 0xDEAD_BEEF,
            asic_id: 0x1FF,
            miner_id: 0x2A,
            ntime: 0xA5,
            mid_id: 0x07,
            valid: 0x0E,
            last_job_nonce2: 0xCAFE_F00D,
        }
    }

    #[test]
    fn status_nonce_payload_valid_len_zero_rejects_padded_tail() {
        let nonce = sample_status_nonce();
        let wire = nonce.encode();
        let mut pkg = MmPkg::simple(Opcode::StatusNonce, RPL, &[]).unwrap();
        pkg.payload[..MINER_NONCE_SIZE].copy_from_slice(&wire);

        assert_eq!(pkg.payload_valid().len(), 0);
        assert!(MinerNonce::decode(pkg.payload_valid()).is_none());
        assert_eq!(MinerNonce::decode(&pkg.payload), Some(nonce));
    }

    #[test]
    fn status_nonce_payload_valid_len_19_rejects_padded_tail() {
        let nonce = sample_status_nonce();
        let wire = nonce.encode();
        let mut pkg =
            MmPkg::simple(Opcode::StatusNonce, RPL, &wire[..MINER_NONCE_SIZE - 1]).unwrap();
        pkg.payload[MINER_NONCE_SIZE - 1] = wire[MINER_NONCE_SIZE - 1];

        assert_eq!(pkg.payload_valid().len(), MINER_NONCE_SIZE - 1);
        assert!(MinerNonce::decode(pkg.payload_valid()).is_none());
        assert_eq!(MinerNonce::decode(&pkg.payload), Some(nonce));
    }

    #[test]
    fn status_nonce_payload_valid_len_20_decodes() {
        let nonce = sample_status_nonce();
        let wire = nonce.encode();
        let pkg = MmPkg::simple(Opcode::StatusNonce, RPL, &wire).unwrap();

        assert_eq!(pkg.payload_valid().len(), MINER_NONCE_SIZE);
        assert_eq!(MinerNonce::decode(pkg.payload_valid()), Some(nonce));
    }

    #[test]
    fn status_nonce_payload_valid_full_payload_decodes() {
        let nonce = sample_status_nonce();
        let wire = nonce.encode();
        let mut payload = [0xA5u8; MM_PKG_PAYLOAD_SIZE];
        payload[..MINER_NONCE_SIZE].copy_from_slice(&wire);
        let pkg = MmPkg::simple(Opcode::StatusNonce, RPL, &payload).unwrap();

        assert_eq!(pkg.payload_valid().len(), MM_PKG_PAYLOAD_SIZE);
        assert_eq!(MinerNonce::decode(pkg.payload_valid()), Some(nonce));
    }
}
