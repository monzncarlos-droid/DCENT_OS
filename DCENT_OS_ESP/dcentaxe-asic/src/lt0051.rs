// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — MSBT0501 / LT0051 Scrypt ASIC driver — SCAFFOLD
//
// Chip:   MSBT0501 (vendor driver name `LT0051`), the Scrypt ASIC in the
//         Hammer/Volc DC0x line (DC02 / DC04 / DC06 / DC08).
// Source:  — a
//         clean-room, instruction-level wire-protocol contract. HARDWARE FACTS
//         ONLY; no vendor code, strings, assets or branding are reproduced.
// Algorithm: scrypt(N=1024, r=1, p=1) — `PowAlgorithm::Scrypt1024`.
//
// ── STATUS: FAIL-CLOSED PRE-HARDWARE SCAFFOLD ───────────────────────────────
// Every `AsicDriver` trait method returns `Err`. The frame builders/parsers
// below ARE real and fully host-tested, because they encode the expensive part
// (the protocol) and are exactly what a bench bring-up needs to replay against
// a logic analyser. What is NOT shipped is the ability to drive live silicon:
// residuals in the protocol contract (§10) remain open. Enabling `init()`
// before they are closed would be guessing at an energised chain.
//
// Open residuals gating live use (all desk-closable, all settled by ONE
// logic-analyser session at power-on):
//   R1  register-command CRC-5 COVERAGE is unproven (§3.4). Three competing
//       hypotheses; we ship ONE named constant, [`REGISTER_COMMAND_CRC5_COVERAGE`].
//   R3  the CRC-16's application to the work frame is inferred from exact
//       geometry, not from a located call site (§4.2).
//
// CLOSED residuals:
//   R2  the final `rev(scratch, 76)` transform on the work payload — **RESOLVED
//       2026-08-02**: it is a plain in-place WHOLE-BUFFER BYTE REVERSE. See
//       [`WORK_PAYLOAD_FINAL_TRANSFORM`] for the proving disassembly.
//       Deliverable:
//       deliverables/W7-RANK-42-MSBT0501.md
//
// ⚠ R2 closing does NOT open the driver. Every `AsicDriver` method still
// returns `Err` — R1/R3 are open and, independently, these boards' rails are
// classified `RailBringup::NoActuator` (nothing in firmware can bring them
// DOWN). Knowledge gained on the work path must never be mistaken for a rail
// that can be cut.
//
// ── THE FOUR MISTAKES THIS FILE EXISTS TO PREVENT (§8) ──────────────────────
//  1. CRC-16 is poly **0x8005** (CRC-16/CMS), NOT Bitmain's 0x1021. The CRC-5
//     IS Bitmain's, which is exactly what makes the CRC-16 tempting to assume.
//  2. The payload is header bytes **[0..75]** (version..nBits). BM1485 uses
//     **[4..79]** — same 76-byte width, different at BOTH ends. The wrong
//     window gives a perfectly-formed, correctly-CRC'd packet and 0 % share
//     acceptance.
//  3. The response nonce is **LITTLE**-endian. BM1485's is big-endian.
//  4. The job id is a plain 7-bit echo used as a **RAW index** into the job
//     table, so the table MUST be 128 entries or it goes out of bounds on the
//     first wrap. Not BM1370's `(id & 0xf0) >> 1`; not BM1368's no-echo.
//
// Scaffold rationale mirrors `bm1373.rs` (ASIC-7): constants and helpers are
// deliberately present-but-unwired so bring-up fills in behaviour, not shape.
#![allow(dead_code, unused_variables)]

use crate::common::*;
use crate::crc::{crc16_cms, crc5_bits};
use crate::serial::SerialPort;

// ── Framing constants (all PROVEN, MSBT0501_PROTOCOL.md §1/§4/§5) ───────────

/// Frame preamble, stored little-endian as `0xCDAB` => wire bytes `AB CD`.
/// Present on EVERY frame, transmit and receive.
pub const PREAMBLE_WIRE: [u8; 2] = [0xAB, 0xCD];

/// Register command frame length.
pub const COMMAND_FRAME_LEN: usize = 12;
/// Register/nonce response frame length. There is NO length field on the wire:
/// results arrive back-to-back in fixed 11-byte strides.
pub const RESPONSE_FRAME_LEN: usize = 11;
/// Work (job) frame length, `0x5D`.
pub const WORK_FRAME_LEN: usize = 93;

/// Offset of the 76-byte scrypt payload inside the work frame.
pub const WORK_PAYLOAD_OFFSET: usize = 0x0F;
/// Scrypt payload length: block-header bytes `[0..75]`.
pub const WORK_PAYLOAD_LEN: usize = 0x4C; // 76
/// Offset of the big-endian CRC-16 in the work frame (`0x0F + 0x4C`).
pub const WORK_CRC16_OFFSET: usize = 0x5B;

/// Work-frame constant at offset `0x02..0x03` (LE) — frame-type discriminator.
/// Value PROVEN; meaning UNKNOWN.
const WORK_FRAME_TYPE: u16 = 0x0001;
/// Command-frame constant at offset `0x02..0x03` (LE). Value PROVEN; meaning
/// UNKNOWN. That it DIFFERS from [`WORK_FRAME_TYPE`] is the evidence the field
/// is a frame-type discriminator at all.
const COMMAND_FRAME_TYPE: u16 = 0x0800;
/// Work-frame constant at offset `0x04..0x05` (LE). Decomposes as
/// `0x158 | (1<<14) | (1<<15)`, both top bits hard-coded on the mining path.
/// Value PROVEN; meaning UNKNOWN — treat as an opaque discriminator.
const WORK_FRAME_DISCRIMINATOR: u16 = 0xC158;

/// Register-command opcodes (`(broadcast << 7) | opcode` at frame offset 4).
const OPCODE_WRITE: u8 = 0x02;
const OPCODE_READ: u8 = 0x03;
/// Broadcast bit position in the opcode byte.
const BROADCAST_BIT: u8 = 0x80;

/// Response type byte at offset 2. A conforming nonce/register response is
/// `0x02`; anything else is dropped.
pub const RESPONSE_TYPE: u8 = 0x02;

// ── Job id (§5.2 — the field that has burned this workspace twice) ──────────

/// Job-id mask. MSBT0501 echoes the id **plainly** as 7 bits.
pub const JOB_ID_MASK: u8 = 0x7F;

/// Job-table length. The received id indexes the table **RAW** — a table
/// smaller than this is an out-of-bounds write on the very first wrap.
/// Do not "optimise" this down to the number of in-flight jobs.
pub const JOB_TABLE_LEN: usize = 128;

/// Next job id: free-running counter, `+1` per job, wrapping at 127.
/// Step is **1** — not 2, 4, 8 or 16 as on various BM13xx parts.
#[inline]
pub const fn next_job_id(current: u8) -> u8 {
    (current.wrapping_add(1)) & JOB_ID_MASK
}

/// Extract the job id from a response frame's byte 7.
///
/// Bit 7 is a reserved flag (BM1485 puts `NONCE_BIT` in the equivalent
/// position) and is DISCARDED — never folded into the id.
#[inline]
pub const fn job_id_from_response(byte7: u8) -> u8 {
    byte7 & JOB_ID_MASK
}

// ── Registers (§6) ──────────────────────────────────────────────────────────

/// UART baud divider.
pub const REG_BAUD_DIVIDER: u8 = 0x01;
/// Broadcast-once init register; written `0x00FF000F`.
pub const REG_INIT_BROADCAST: u8 = 0x02;
/// PLL0 parameter.
pub const REG_PLL0: u8 = 0x03;
/// PLL1 parameter.
pub const REG_PLL1: u8 = 0x04;
/// Chip-detect / PLL-lock probe (read), argument `0x4BF`.
pub const REG_CHIP_DETECT: u8 = 0x10;
/// Soft reset: write 4, wait 100 ms, write 0.
pub const REG_SOFT_RESET: u8 = 0x15;
/// Active PLL select (`0` or `1`).
pub const REG_PLL_SELECT: u8 = 0x22;

/// Value broadcast to [`REG_INIT_BROADCAST`] during init.
pub const INIT_BROADCAST_VALUE: u32 = 0x00FF_000F;
/// Argument used with the [`REG_CHIP_DETECT`] read.
pub const CHIP_DETECT_ARG: u32 = 0x4BF;

/// Ticket mask for DC02 / DC04 / DC06.
///
/// ⚠ **HIGH-bits convention** — the opposite of BM13xx. Do not invert it by
/// analogy with the Bitmain drivers in this crate.
pub const TICKET_MASK_DEFAULT: u32 = 0xFFFE_0000;
/// Ticket mask configured for DC08 (3 bits wider). DC08 is NOT a registered
/// board here — the constant is recorded for completeness only.
pub const TICKET_MASK_DC08: u32 = 0xFFFF_C000;

/// Init delays that must be honoured (§6). The 1 s post-reset settle before
/// the second PLL check is not optional — the vendor aborts bring-up on a
/// failed second check.
pub const INIT_DELAY_AFTER_BROADCAST_MS: u32 = 5;
pub const INIT_DELAY_SOFT_RESET_MS: u32 = 100;
pub const INIT_DELAY_POST_RESET_MS: u32 = 1000;

// ── PLL solver constraints (§6) ─────────────────────────────────────────────

pub const PLL_REF_MHZ: u32 = 25;
pub const PLL_REFDIV_RANGE: core::ops::RangeInclusive<u32> = 1..=3;
pub const PLL_FBDIV_RANGE: core::ops::RangeInclusive<u32> = 80..=480;
pub const PLL_PFD_MHZ_RANGE: core::ops::RangeInclusive<u32> = 7..=200;
pub const PLL_VCO_MHZ_RANGE: core::ops::RangeInclusive<u32> = 4000..=8000;

/// Vendor firmware frequency clamp. ⚠ NOT a safe operating envelope — it is
/// simply what the vendor app permits. Board profiles pin their own,
/// bench-bounded defaults.
pub const VENDOR_FREQ_MIN_MHZ: f32 = 700.0;
pub const VENDOR_FREQ_MAX_MHZ: f32 = 2600.0;
/// Vendor stock default frequency (`0x8FC`).
pub const VENDOR_FREQ_DEFAULT_MHZ: f32 = 2300.0;

/// Initial UART configuration: 115200 8N1, no flow control.
pub const INITIAL_BAUD: u32 = 115_200;

/// Baud divider codes for [`REG_BAUD_DIVIDER`].
pub const fn baud_divider_code(baud: u32) -> Option<u8> {
    match baud {
        25_000_000 => Some(0x01),
        12_500_000 => Some(0x03),
        3_125_000 => Some(0x00),
        115_200 => Some(0x1A),
        _ => None,
    }
}

// ── R1: register-command CRC-5 coverage (§3.4 — GENUINELY OPEN) ─────────────

/// Which bytes of a 12-byte register command the CRC-5 in byte 11 covers.
///
/// ⚠ **UNPROVEN.** The protocol contract (§3.4) states three competing
/// hypotheses and closes none of them:
///   A. bytes 5..10 (48 bits) — both vendor builders copy exactly that range
///      into a scratch immediately before an untraced stage;
///   B. bytes 2..10 (72 bits) — symmetric with the PROVEN receive rule
///      ("everything after the preamble, excluding the CRC byte");
///   C. transmitted as 0 — byte 11 is only ever written as `0 & 0x1F`, and the
///      CRC-5 routine has exactly one caller image-wide: the RECEIVE validator.
///
/// The contract's instruction: "Do not ship a driver that asserts a command
/// CRC coverage. Emit hypothesis B if a value must be chosen, but make it a
/// single named constant so it can be corrected after one capture."
///
/// This is that constant. A wrong value corrupts nothing — the chip simply
/// ignores the command — but it presents as "chip never enumerates", which is
/// historically a multi-day burn. It is one reason [`Lt0051::init`] refuses.
pub const REGISTER_COMMAND_CRC5_COVERAGE: Crc5Coverage = Crc5Coverage::AfterPreambleHypothesisB;

/// Candidate CRC-5 coverages for a register command (see
/// [`REGISTER_COMMAND_CRC5_COVERAGE`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Crc5Coverage {
    /// Hypothesis A: bytes 5..=10 (48 bits).
    ScratchRangeHypothesisA,
    /// Hypothesis B: bytes 2..=10 (72 bits) — the receive-symmetric rule.
    AfterPreambleHypothesisB,
    /// Hypothesis C: the field is transmitted as zero and never checked.
    TransmittedZeroHypothesisC,
}

impl Crc5Coverage {
    /// Byte range of the 12-byte command frame this coverage spans.
    pub const fn byte_range(self) -> Option<(usize, usize)> {
        match self {
            Crc5Coverage::ScratchRangeHypothesisA => Some((5, 11)),
            Crc5Coverage::AfterPreambleHypothesisB => Some((2, 11)),
            Crc5Coverage::TransmittedZeroHypothesisC => None,
        }
    }
}

// ── R2: the payload transform (§4.3) — RESOLVED 2026-08-02 ──────────────────

/// The vendor's work-payload assembly ends with `rev(scratch, 76)`. That helper
/// (IROM `0x420fddd0`, called from `0x42016c76`) is now disassembled: it is a
/// plain **in-place whole-buffer BYTE reversal**.
///
/// ```text
/// 420fddd0:  36 41 00     entry   a1, 32
/// 420fddd3:  30 91 41     srli    a9, a3, 1      ; iterations = len >> 1  (38)
/// 420fddd6:  9c 69        beqz.n  a9, 0x420fddf0
/// 420fddd8:  0b 33        addi.n  a3, a3, -1
/// 420fddda:  30 82 80     add     a8, a2, a3     ; tail = buf + len - 1
/// 420fdddd:  76 89 0f     loop    a9, 0x420fddf0
/// 420fdde0:  b2 08 00     l8ui    a11, a8, 0     ;   swap *head <-> *tail
/// 420fdde3:  a2 02 00     l8ui    a10, a2, 0
/// 420fdde6:  b2 42 00     s8i     a11, a2, 0
/// 420fdde9:  a2 48 00     s8i     a10, a8, 0
/// 420fddec:  1b 22        addi.n  a2, a2, 1      ;   head++
/// 420fddee:  0b 88        addi.n  a8, a8, -1     ;   tail--
/// 420fddf0:  1d f0        retw.n
/// ```
///
/// `PerWordByteReverse` is positively **excluded**, not merely un-preferred:
/// the loop count is `len >> 1` (38 = a full 76-byte reversal), the pointers
/// converge across the whole buffer with no 4-byte stride, and every memory
/// access is `l8ui`/`s8i` — there is no 32-bit load or store anywhere in the
/// function. (The image's real word-swap helper lives 56 bytes later at
/// `0x420fde08` and looks nothing like this; it is the `store_be32` used for
/// version/ntime/nbits.)
///
/// Call-site linkage is proven through the literal pool rather than assumed:
/// the `callx8` at `0x42016c76` loads `l32r a8, 0x420020c4`, and that literal
/// holds `0x420fddd0`. Arguments are `a10 = scratch` / `a11 = 76`, which become
/// `a2 = buf` / `a3 = len` after `entry`.
///
/// Corroborated byte-identical in **5 of 5** relevant held miner images (DC02
/// v1.0.2 and v2.0.2, DC04, DC06, BC01) — all three Hammer Scrypt boards plus
/// one BC-line board, across a major version bump, so it is a lineage-level
/// primitive rather than a per-model quirk. It is **absent** from the two
/// BC04/Thor images, which are a separate lineage at a different major version
/// and carry none of the Scrypt boards.
///
/// Evidence:
/// W7-RANK-42-MSBT0501.md`. `MSBT0501_PROTOCOL.md` §4.3 still records this as
/// UNKNOWN and should be updated to point there.
///
/// ⚠ This constant being resolved does **not** authorize sending work. `init()`
/// and `send_work()` still refuse: R1 and R3 are open, and the rail gate is
/// entirely separate. See [`apply_payload_final_transform`].
pub const WORK_PAYLOAD_FINAL_TRANSFORM: PayloadTransform = PayloadTransform::WholeBufferByteReverse;

/// The final whole-buffer transform applied to the 76-byte scrypt payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadTransform {
    /// UNDECODED — the driver must refuse to send work.
    Unresolved,
    /// Reverse all 76 bytes.
    WholeBufferByteReverse,
    /// Reverse bytes within each 4-byte word.
    PerWordByteReverse,
    /// No transform.
    Identity,
}

// ── Frame construction / parsing (all host-tested) ──────────────────────────

/// Assemble the 76-byte scrypt payload from a job, **pre**-final-transform.
///
/// 🔴 THE WINDOW: this is block-header bytes `[0..75]` —
/// `version ‖ prevhash ‖ merkle_root ‖ ntime ‖ nbits`. Version IN, nonce OUT.
/// BM1485 uses `[4..79]` (version dropped, nonce included): the SAME 76-byte
/// width, shifted 4 bytes at BOTH ends. Getting it wrong yields a valid-looking
/// packet and zero accepted shares.
///
/// There is **no midstate** — scrypt cannot be split at a block boundary, so
/// the host hands over header material directly and the chip supplies the
/// nonce itself.
///
/// The 32-bit scalars are stored **big-endian** (`bswap32` in the vendor
/// assembler); `prev_block_hash` and `merkle_root` are copied verbatim.
pub fn assemble_scrypt_payload(job: &MiningJob) -> [u8; WORK_PAYLOAD_LEN] {
    let mut payload = [0u8; WORK_PAYLOAD_LEN];
    payload[0x00..0x04].copy_from_slice(&job.version.to_be_bytes());
    payload[0x04..0x24].copy_from_slice(&job.prev_block_hash);
    payload[0x24..0x44].copy_from_slice(&job.merkle_root);
    payload[0x44..0x48].copy_from_slice(&job.ntime.to_be_bytes());
    payload[0x48..0x4C].copy_from_slice(&job.nbits.to_be_bytes());
    payload
}

/// Apply the vendor's final whole-buffer transform (R2, §4.3) in place.
///
/// The proven transform is [`PayloadTransform::WholeBufferByteReverse`] — see
/// [`WORK_PAYLOAD_FINAL_TRANSFORM`] for the disassembly that establishes it.
/// This function takes the transform as a parameter rather than reading the
/// constant directly so the choice is testable independently of the wiring, and
/// so an `Unresolved` value can never silently degrade to a no-op: it returns
/// `Err` and leaves the buffer untouched.
pub fn apply_payload_final_transform(
    payload: &mut [u8; WORK_PAYLOAD_LEN],
    transform: PayloadTransform,
) -> Result<(), AsicError> {
    match transform {
        PayloadTransform::Unresolved => Err(AsicError::InitFailed(
            "LT0051 payload final transform is unresolved; refusing to emit a \
             work payload rather than guess (MSBT0501_PROTOCOL.md §4.3)"
                .to_string(),
        )),
        PayloadTransform::WholeBufferByteReverse => {
            payload.reverse();
            Ok(())
        }
        PayloadTransform::PerWordByteReverse => {
            for word in payload.chunks_exact_mut(4) {
                word.reverse();
            }
            Ok(())
        }
        PayloadTransform::Identity => Ok(()),
    }
}

/// Assemble the 76-byte payload in **wire order** — [`assemble_scrypt_payload`]
/// followed by [`WORK_PAYLOAD_FINAL_TRANSFORM`].
///
/// Because the three 32-bit scalars are stored big-endian and are then caught by
/// a whole-buffer reversal, each lands little-endian **and the field order is
/// inverted**:
///
/// ```text
/// pre-rev:  version_BE ‖ prevhash[0..31] ‖ merkle[0..31] ‖ ntime_BE ‖ nbits_BE
/// wire:     nbits_LE ‖ ntime_LE ‖ rev(merkle) ‖ rev(prevhash) ‖ version_LE
/// ```
///
/// ⚠ That wire layout is a *derived* consequence of two proven facts (the §4.3
/// assembly order and the reversal). No capture of a real 93-byte work frame has
/// been compared against it — one logic-analyser frame confirms it and settles
/// R3 at the same time. This helper is for bench replay, not for live dispatch:
/// `send_work` still refuses.
pub fn assemble_scrypt_payload_wire(job: &MiningJob) -> Result<[u8; WORK_PAYLOAD_LEN], AsicError> {
    let mut payload = assemble_scrypt_payload(job);
    apply_payload_final_transform(&mut payload, WORK_PAYLOAD_FINAL_TRANSFORM)?;
    Ok(payload)
}

/// Build the 93-byte work frame (§4.2).
///
/// Layout:
/// ```text
/// 0x00  2  preamble 0xCDAB (LE)          -> AB CD
/// 0x02  2  0x0001 (LE)                   frame type
/// 0x04  2  0xC158 (LE)                   opaque discriminator
/// 0x06  2  chip address | (flags << 8)
/// 0x08  1  0x00
/// 0x09  1  0x00
/// 0x0A  1  job id & 0x7F
/// 0x0B  4  start nonce, LITTLE-endian
/// 0x0F 76  scrypt payload
/// 0x5B  2  CRC-16/CMS over bytes 2..=0x5A, BIG-endian
/// ```
pub fn build_work_frame(
    chip_address: u8,
    flags: u8,
    job_id: u8,
    start_nonce: u32,
    payload: &[u8; WORK_PAYLOAD_LEN],
) -> [u8; WORK_FRAME_LEN] {
    let mut frame = [0u8; WORK_FRAME_LEN];
    frame[0x00..0x02].copy_from_slice(&PREAMBLE_WIRE);
    frame[0x02..0x04].copy_from_slice(&WORK_FRAME_TYPE.to_le_bytes());
    frame[0x04..0x06].copy_from_slice(&WORK_FRAME_DISCRIMINATOR.to_le_bytes());
    frame[0x06] = chip_address;
    frame[0x07] = flags;
    frame[0x08] = 0x00;
    frame[0x09] = 0x00;
    frame[0x0A] = job_id & JOB_ID_MASK;
    // Start nonce is LITTLE-endian (four bytes written from shifts 0/8/16/24
    // into ascending addresses).
    frame[0x0B..0x0F].copy_from_slice(&start_nonce.to_le_bytes());
    frame[WORK_PAYLOAD_OFFSET..WORK_PAYLOAD_OFFSET + WORK_PAYLOAD_LEN].copy_from_slice(payload);
    // CRC-16/CMS (poly 0x8005 — NOT 0x1021) over everything after the
    // preamble up to but excluding the CRC itself, transmitted BIG-endian.
    let crc = crc16_cms(&frame[2..WORK_CRC16_OFFSET]);
    frame[WORK_CRC16_OFFSET] = (crc >> 8) as u8;
    frame[WORK_CRC16_OFFSET + 1] = (crc & 0xFF) as u8;
    frame
}

/// Build a 12-byte register command (§4.1).
///
/// `value` is stored **big-endian** and is zero on a read. Byte 11 carries the
/// CRC-5 in its low 5 bits under [`REGISTER_COMMAND_CRC5_COVERAGE`] — see that
/// constant for the open question.
pub fn build_register_command(
    broadcast: bool,
    write: bool,
    chip_address: u8,
    register: u8,
    value: u32,
) -> [u8; COMMAND_FRAME_LEN] {
    let mut frame = [0u8; COMMAND_FRAME_LEN];
    frame[0x00..0x02].copy_from_slice(&PREAMBLE_WIRE);
    frame[0x02..0x04].copy_from_slice(&COMMAND_FRAME_TYPE.to_le_bytes());
    let opcode = if write { OPCODE_WRITE } else { OPCODE_READ };
    frame[0x04] = if broadcast { BROADCAST_BIT } else { 0 } | opcode;
    frame[0x05] = chip_address;
    frame[0x06] = register;
    frame[0x07..0x0B].copy_from_slice(&if write { value } else { 0 }.to_be_bytes());
    frame[0x0B] = match REGISTER_COMMAND_CRC5_COVERAGE.byte_range() {
        Some((start, end)) => crc5_bits(&frame[start..end], (end - start) * 8) & 0x1F,
        None => 0,
    };
    frame
}

/// A decoded nonce/register response (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lt0051Response {
    /// Nonce, reassembled from bytes 3..=6 **little-endian** (byte 3 = LSB).
    pub nonce: u32,
    /// Job id from byte 7, masked `& 0x7F`. Safe to use as a RAW index into a
    /// [`JOB_TABLE_LEN`]-entry table.
    pub job_id: u8,
    /// Status/aux bytes 8..=9. Present and PROVEN; semantics UNKNOWN, so they
    /// are surfaced verbatim rather than interpreted.
    pub aux: [u8; 2],
}

/// Parse one 11-byte response frame.
///
/// Returns `None` on a preamble mismatch, an unexpected type byte, or a CRC-5
/// failure. Only the **low 5 bits** of byte 10 are compared: the vendor
/// compares the whole byte, but bits 5..7 are reserved flag space on the
/// BM1485-family layout, and replicating the vendor's stricter test would drop
/// otherwise-valid responses (§3.3, flagged there as a recommendation).
pub fn parse_response(frame: &[u8; RESPONSE_FRAME_LEN]) -> Option<Lt0051Response> {
    if frame[0..2] != PREAMBLE_WIRE {
        return None;
    }
    if frame[2] != RESPONSE_TYPE {
        return None;
    }
    // CRC-5 over bytes 2..=9 = 64 bits, compared against byte 10's low 5 bits.
    let expected = crc5_bits(&frame[2..10], 64) & 0x1F;
    if (frame[10] & 0x1F) != expected {
        return None;
    }
    Some(Lt0051Response {
        // LITTLE-endian: byte 3 is the LSB. BM1485's is big-endian; swapping
        // this yields valid-looking but always-rejected shares.
        nonce: u32::from_le_bytes([frame[3], frame[4], frame[5], frame[6]]),
        job_id: job_id_from_response(frame[7]),
        aux: [frame[8], frame[9]],
    })
}

/// Split a raw UART read into fixed 11-byte response strides.
///
/// The response frame has no length field; multiple results arrive
/// back-to-back in one read. A trailing partial frame is dropped.
pub fn parse_response_stream(rx: &[u8]) -> Vec<Lt0051Response> {
    rx.chunks_exact(RESPONSE_FRAME_LEN)
        .filter_map(|chunk| {
            let mut frame = [0u8; RESPONSE_FRAME_LEN];
            frame.copy_from_slice(chunk);
            parse_response(&frame)
        })
        .collect()
}

/// Chip address interval for a chain of `chip_count` chips: `0x100 / count`.
///
/// A one-chip chain skips address assignment entirely in the vendor firmware,
/// so it has no interval.
pub const fn address_interval(chip_count: u8) -> Option<u8> {
    if chip_count <= 1 {
        return None;
    }
    Some((0x100u16 / chip_count as u16) as u8)
}

// ── Driver ──────────────────────────────────────────────────────────────────

fn scaffold_disabled(op: &str) -> AsicError {
    AsicError::InitFailed(format!(
        "LT0051 (MSBT0501) {op} is a pre-hardware scaffold and is disabled: the \
         register-command CRC-5 coverage (R1) and the CRC-16's application to the \
         work frame (R3) are unresolved (MSBT0501_PROTOCOL.md §3.4, §4.2). The \
         payload transform (R2, §4.3) IS resolved and is not a reason for this \
         refusal. Independently, these boards classify as RailBringup::NoActuator \
         — nothing in firmware can bring their rail down. Close R1/R3 with a \
         logic-analyser capture, and the rail separately, before driving live \
         silicon."
    ))
}

/// MSBT0501 / LT0051 Scrypt driver — fail-closed scaffold.
pub struct Lt0051 {
    serial: SerialPort,
    chip_count: u8,
    current_frequency: f32,
    address_interval: u8,
    next_job_id: u8,
}

impl Lt0051 {
    pub fn new(serial: SerialPort) -> Self {
        Self {
            serial,
            chip_count: 0,
            current_frequency: 0.0,
            address_interval: 0,
            next_job_id: 0,
        }
    }

    /// Advance the internal job-id counter (`+1`, wrapping at 127).
    fn take_job_id(&mut self) -> u8 {
        let id = self.next_job_id;
        self.next_job_id = next_job_id(id);
        id
    }
}

impl crate::AsicDriver for Lt0051 {
    fn init(
        &mut self,
        frequency: f32,
        chain_count: u8,
        initial_difficulty: f64,
    ) -> Result<u8, AsicError> {
        // Init ordering is fully documented (§6): PLL check -> broadcast 0x02
        // -> 5 ms -> address assignment -> frequency -> soft reset (4, 100 ms,
        // 0) -> 1000 ms -> PLL check -> ticket mask -> SRAM configure. It is
        // NOT executed here: enumerating requires transmitting register
        // commands whose CRC-5 coverage is unproven (R1), and a wrong command
        // CRC presents exactly as "chip never enumerates".
        log::warn!("LT0051 init: SCAFFOLD — refusing (protocol residuals R1/R2 open)");
        Err(scaffold_disabled("init"))
    }

    fn send_work(&mut self, job: &MiningJob) -> Result<(), AsicError> {
        // `build_work_frame` + `assemble_scrypt_payload` are complete and
        // tested; the missing piece is the final rev() transform (R2). A wrong
        // transform is invisible on the wire and costs 100 % of shares.
        log::warn!("LT0051 send_work: SCAFFOLD — payload final transform unresolved (R2)");
        Err(scaffold_disabled("send_work"))
    }

    fn process_work(&mut self, rx_buf: &[u8]) -> Result<Vec<AsicResult>, AsicError> {
        // Parsing IS implemented (`parse_response_stream`), but mapping a
        // response to a chip index needs the enumeration `init` refuses to run.
        log::warn!("LT0051 process_work: SCAFFOLD — chain not enumerated");
        Err(scaffold_disabled("process_work"))
    }

    fn set_frequency(&mut self, target_freq: f32) -> Result<(), AsicError> {
        // Frequency change is glitch-free BY CONSTRUCTION on this chip: the
        // PLL index ping-pongs 0<->1 so the INACTIVE PLL is reprogrammed and
        // only then selected via reg 0x22. A driver that reprograms the ACTIVE
        // PLL glitches the hash clock — do not "simplify" that away when this
        // is implemented.
        log::warn!("LT0051 set_frequency: SCAFFOLD — not implemented");
        Err(scaffold_disabled("set_frequency"))
    }

    fn set_version_mask(&mut self, mask: u32) -> Result<(), AsicError> {
        // Scrypt has no BIP320/AsicBoost equivalent; the header version is a
        // plain field. This is a hard error rather than a silent no-op so a
        // caller that tries to roll version on a Scrypt chain is caught.
        log::warn!("LT0051 set_version_mask: Scrypt has no version rolling");
        Err(AsicError::InitFailed(
            "LT0051 mines scrypt, which has no version rolling (BIP320/AsicBoost \
             does not apply) — the caller should gate on \
             PowAlgorithm::supports_version_rolling()"
                .into(),
        ))
    }

    fn read_registers(&mut self) -> Result<Vec<RegisterData>, AsicError> {
        Err(scaffold_disabled("read_registers"))
    }

    fn chip_count(&self) -> u8 {
        self.chip_count
    }

    fn current_frequency(&self) -> f32 {
        self.current_frequency
    }

    fn read_responses(&mut self, _timeout_ms: u16) -> Result<Vec<AsicResult>, AsicError> {
        Err(scaffold_disabled("read_responses"))
    }

    fn set_difficulty(&mut self, difficulty: f64) -> Result<(), AsicError> {
        // Maps to the ticket mask, which is a HIGH-bits convention here — the
        // opposite of BM13xx. `common::get_difficulty_mask` must NOT be reused.
        log::warn!("LT0051 set_difficulty: SCAFFOLD — ticket-mask encoding not implemented");
        Err(scaffold_disabled("set_difficulty"))
    }

    fn set_max_baud(&mut self) -> Result<u32, AsicError> {
        Err(scaffold_disabled("set_max_baud"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_job() -> MiningJob {
        let mut prev = [0u8; 32];
        let mut merkle = [0u8; 32];
        for i in 0..32 {
            prev[i] = 0xA0 + i as u8;
            merkle[i] = 0x40 + i as u8;
        }
        MiningJob::new_full(0x11, 0x2000_0004, prev, merkle, 0x6789_ABCD, 0x1D00_FFFF, 0)
    }

    /// The 80-byte block header the same job describes, in canonical
    /// little-endian-scalar wire order — used to prove the payload window.
    fn test_header_80(job: &MiningJob) -> [u8; 80] {
        let mut h = [0u8; 80];
        h[0..4].copy_from_slice(&job.version.to_be_bytes());
        h[4..36].copy_from_slice(&job.prev_block_hash);
        h[36..68].copy_from_slice(&job.merkle_root);
        h[68..72].copy_from_slice(&job.ntime.to_be_bytes());
        h[72..76].copy_from_slice(&job.nbits.to_be_bytes());
        h[76..80].copy_from_slice(&0u32.to_be_bytes()); // nonce
        h
    }

    // ── 🔴 The payload window (§8 #2) ───────────────────────────────────────

    #[test]
    fn payload_is_header_bytes_0_to_75_not_bm1485s_4_to_79() {
        let job = test_job();
        let payload = assemble_scrypt_payload(&job);
        let header = test_header_80(&job);

        assert_eq!(payload.len(), 76);
        assert_eq!(
            payload.as_slice(),
            &header[0..76],
            "MSBT0501 sends header[0..75]: version IN, nonce OUT"
        );
        assert_ne!(
            payload.as_slice(),
            &header[4..80],
            "header[4..79] is the BM1485 window — same width, wrong at BOTH ends. \
             Using it gives a perfectly-formed packet and 0% share acceptance."
        );

        // Field-by-field, so a single mis-sized copy is localised.
        assert_eq!(&payload[0x00..0x04], &job.version.to_be_bytes());
        assert_eq!(&payload[0x04..0x24], &job.prev_block_hash);
        assert_eq!(&payload[0x24..0x44], &job.merkle_root);
        assert_eq!(&payload[0x44..0x48], &job.ntime.to_be_bytes());
        assert_eq!(&payload[0x48..0x4C], &job.nbits.to_be_bytes());
    }

    #[test]
    fn payload_carries_no_midstate() {
        // Scrypt cannot be split at a midstate. A job with midstates populated
        // (BM1397-style) must not leak any of them into the payload.
        let mut job = test_job();
        job.midstates = vec![[0xEE; 32], [0xEF; 32]];
        let payload = assemble_scrypt_payload(&job);
        assert!(
            !payload.windows(32).any(|w| w == [0xEEu8; 32]),
            "a midstate must never reach the LT0051 payload"
        );
    }

    // ── Work frame geometry (§4.2) ──────────────────────────────────────────

    #[test]
    fn work_frame_layout_is_byte_exact() {
        let job = test_job();
        let payload = assemble_scrypt_payload(&job);
        let frame = build_work_frame(0x80, 0x00, 0x11, 0x0000_0000, &payload);

        assert_eq!(frame.len(), 93);
        assert_eq!(&frame[0x00..0x02], &[0xAB, 0xCD], "preamble on the wire");
        assert_eq!(&frame[0x02..0x04], &[0x01, 0x00], "0x0001 stored LE");
        assert_eq!(&frame[0x04..0x06], &[0x58, 0xC1], "0xC158 stored LE");
        assert_eq!(frame[0x06], 0x80, "chip address");
        assert_eq!(frame[0x0A], 0x11, "job id at 0x0A");
        assert_eq!(
            &frame[WORK_PAYLOAD_OFFSET..WORK_PAYLOAD_OFFSET + WORK_PAYLOAD_LEN],
            payload.as_slice()
        );
        // Geometry closes exactly: 0x0F + 0x4C = 0x5B, + 2 = 0x5D.
        assert_eq!(WORK_PAYLOAD_OFFSET + WORK_PAYLOAD_LEN, WORK_CRC16_OFFSET);
        assert_eq!(WORK_CRC16_OFFSET + 2, WORK_FRAME_LEN);
    }

    #[test]
    fn work_frame_start_nonce_is_little_endian() {
        let payload = [0u8; WORK_PAYLOAD_LEN];
        let frame = build_work_frame(0, 0, 0, 0x1122_3344, &payload);
        assert_eq!(
            &frame[0x0B..0x0F],
            &[0x44, 0x33, 0x22, 0x11],
            "start nonce is LE (LSB first)"
        );
    }

    #[test]
    fn work_frame_job_id_is_masked_to_seven_bits() {
        let payload = [0u8; WORK_PAYLOAD_LEN];
        let frame = build_work_frame(0, 0, 0xFF, 0, &payload);
        assert_eq!(frame[0x0A], 0x7F, "job id is `& 0x7F` on transmit");
    }

    // ── 🔴 The CRC-16 trap (§8 #1) ──────────────────────────────────────────

    #[test]
    fn work_frame_crc16_is_cms_0x8005_not_bitmain_0x1021() {
        let job = test_job();
        let payload = assemble_scrypt_payload(&job);
        let frame = build_work_frame(0x00, 0x00, 0x05, 0, &payload);

        let cms = crc16_cms(&frame[2..WORK_CRC16_OFFSET]);
        let bitmain = crate::crc::crc16_false(&frame[2..WORK_CRC16_OFFSET]);
        assert_ne!(cms, bitmain, "the two CRC-16s must not coincide here");

        // Big-endian on the wire.
        assert_eq!(frame[WORK_CRC16_OFFSET], (cms >> 8) as u8);
        assert_eq!(frame[WORK_CRC16_OFFSET + 1], (cms & 0xFF) as u8);
        assert_ne!(
            frame[WORK_CRC16_OFFSET],
            (bitmain >> 8) as u8,
            "a regression to crc16_false must be visible in the frame bytes"
        );

        // Coverage starts AFTER the preamble.
        let mut poisoned = frame;
        poisoned[0] ^= 0xFF;
        assert_eq!(
            crc16_cms(&poisoned[2..WORK_CRC16_OFFSET]),
            cms,
            "the preamble is NOT covered by the work CRC"
        );
    }

    #[test]
    fn crc16_cms_check_value_is_reachable_from_this_module() {
        // The contract's explicit instruction: "Pin crc16(b\"123456789\") ==
        // 0xAEE7 in a unit test." Pinned here too so deleting the crc.rs test
        // still leaves the LT0051 lane protected.
        assert_eq!(crc16_cms(b"123456789"), 0xAEE7);
    }

    // ── Response parsing (§5) ───────────────────────────────────────────────

    fn make_response(nonce: u32, job_id: u8, aux: [u8; 2]) -> [u8; RESPONSE_FRAME_LEN] {
        let mut f = [0u8; RESPONSE_FRAME_LEN];
        f[0..2].copy_from_slice(&PREAMBLE_WIRE);
        f[2] = RESPONSE_TYPE;
        f[3..7].copy_from_slice(&nonce.to_le_bytes());
        f[7] = job_id;
        f[8] = aux[0];
        f[9] = aux[1];
        f[10] = crc5_bits(&f[2..10], 64) & 0x1F;
        f
    }

    #[test]
    fn response_nonce_is_little_endian_not_bm1485s_big_endian() {
        let f = make_response(0xDEAD_BEEF, 0x05, [0x12, 0x34]);
        // Wire order proof: byte 3 holds the LSB.
        assert_eq!(&f[3..7], &[0xEF, 0xBE, 0xAD, 0xDE]);
        let r = parse_response(&f).expect("valid response");
        assert_eq!(r.nonce, 0xDEAD_BEEF);
        assert_ne!(
            r.nonce,
            u32::from_be_bytes([f[3], f[4], f[5], f[6]]),
            "reading the nonce big-endian (the BM1485 rule) gives valid-looking \
             but always-rejected shares"
        );
        assert_eq!(r.aux, [0x12, 0x34]);
    }

    #[test]
    fn response_job_id_discards_bit_seven_and_is_a_safe_raw_table_index() {
        // Bit 7 is reserved flag space (NONCE_BIT on BM1485) and must never be
        // folded into the id.
        let f = make_response(1, 0x80 | 0x05, [0, 0]);
        let r = parse_response(&f).expect("valid response");
        assert_eq!(r.job_id, 0x05);

        // 🔴 The out-of-bounds trap: the id indexes the job table RAW, so the
        // table must be 128 entries. Prove EVERY reachable id is in range.
        let table = [0u8; JOB_TABLE_LEN];
        for raw in 0u8..=0xFF {
            let id = job_id_from_response(raw);
            assert!(
                (id as usize) < table.len(),
                "job id {id} from byte 0x{raw:02x} escapes a {}-entry table",
                table.len()
            );
        }
        assert_eq!(JOB_TABLE_LEN, 128);
    }

    #[test]
    fn job_id_counter_steps_by_one_and_wraps_at_127() {
        // Not +2/+4/+8/+16 as on various BM13xx parts.
        assert_eq!(next_job_id(0), 1);
        assert_eq!(next_job_id(1), 2);
        assert_eq!(next_job_id(126), 127);
        assert_eq!(next_job_id(127), 0, "wraps at 127, not 255");

        // A full cycle visits exactly 128 distinct ids, every one a legal index.
        let mut seen = [false; JOB_TABLE_LEN];
        let mut id = 0u8;
        for _ in 0..JOB_TABLE_LEN {
            assert!(!seen[id as usize]);
            seen[id as usize] = true;
            id = next_job_id(id);
        }
        assert_eq!(id, 0, "cycle length is exactly the table length");
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn response_rejects_bad_preamble_type_and_crc() {
        let good = make_response(0x1234, 7, [0, 0]);
        assert!(parse_response(&good).is_some());

        let mut bad_preamble = good;
        bad_preamble[0] = 0x00;
        assert!(parse_response(&bad_preamble).is_none());

        let mut bad_type = good;
        bad_type[2] = 0x03;
        assert!(parse_response(&bad_type).is_none());

        let mut bad_crc = good;
        bad_crc[10] ^= 0x01;
        assert!(parse_response(&bad_crc).is_none(), "CRC-5 must be enforced");

        // A flipped payload bit is caught by the CRC too.
        let mut bit_flip = good;
        bit_flip[4] ^= 0x80;
        assert!(parse_response(&bit_flip).is_none());
    }

    #[test]
    fn response_crc_compares_only_the_low_five_bits() {
        // The vendor compares the whole byte; bits 5..7 are reserved flags on
        // the BM1485-family layout, so replicating the stricter test would drop
        // otherwise-valid responses (§3.3 recommendation).
        let mut f = make_response(0x99, 3, [0, 0]);
        f[10] |= 0b1110_0000;
        assert!(
            parse_response(&f).is_some(),
            "reserved flag bits 5..7 must not fail the CRC check"
        );
    }

    #[test]
    fn response_stream_splits_fixed_eleven_byte_strides() {
        let a = make_response(0x0000_0001, 1, [0, 0]);
        let b = make_response(0x8000_0002, 2, [0, 0]);
        let mut rx = Vec::new();
        rx.extend_from_slice(&a);
        rx.extend_from_slice(&b);
        rx.extend_from_slice(&b[..5]); // trailing partial frame
        let parsed = parse_response_stream(&rx);
        assert_eq!(parsed.len(), 2, "a trailing partial frame is dropped");
        assert_eq!(parsed[0].nonce, 0x0000_0001);
        assert_eq!(parsed[1].nonce, 0x8000_0002);
    }

    // ── Register commands + the OPEN CRC-5 coverage (§3.4, R1) ──────────────

    #[test]
    fn register_command_layout_and_opcode_split() {
        let w = build_register_command(false, true, 0x40, REG_PLL0, 0x1122_3344);
        assert_eq!(w.len(), 12);
        assert_eq!(&w[0..2], &[0xAB, 0xCD]);
        assert_eq!(&w[2..4], &[0x00, 0x08], "0x0800 stored LE");
        assert_eq!(w[4], 0x02, "write opcode");
        assert_eq!(w[5], 0x40);
        assert_eq!(w[6], REG_PLL0);
        assert_eq!(&w[7..11], &[0x11, 0x22, 0x33, 0x44], "value is BIG-endian");

        let r = build_register_command(true, false, 0x00, REG_CHIP_DETECT, 0xFFFF_FFFF);
        assert_eq!(r[4], 0x80 | 0x03, "broadcast bit | read opcode");
        assert_eq!(&r[7..11], &[0, 0, 0, 0], "value is zeroed on a read");

        // The command frame type must DIFFER from the work frame type — that
        // difference is the evidence the field discriminates frame kind.
        assert_ne!(COMMAND_FRAME_TYPE, WORK_FRAME_TYPE);
    }

    #[test]
    fn register_command_crc5_is_one_named_constant_for_the_open_question() {
        // The contract forbids ASSERTING a coverage. What we can pin is that
        // the choice is a single named constant and that byte 11 stays a 5-bit
        // field whatever it is set to.
        assert_eq!(
            REGISTER_COMMAND_CRC5_COVERAGE,
            Crc5Coverage::AfterPreambleHypothesisB,
            "if a capture settles §3.4, change THIS constant — not the builder"
        );
        for (broadcast, write, reg, val) in [
            (false, true, REG_PLL0, 0x1122_3344u32),
            (true, false, REG_CHIP_DETECT, 0),
            (true, true, REG_SOFT_RESET, 4),
        ] {
            let f = build_register_command(broadcast, write, 0x00, reg, val);
            assert_eq!(f[0x0B] & 0xE0, 0, "byte 11 must stay a 5-bit field");
        }
        // All three hypotheses stay expressible, so correcting after a capture
        // is a one-line change.
        assert_eq!(
            Crc5Coverage::AfterPreambleHypothesisB.byte_range(),
            Some((2, 11))
        );
        assert_eq!(
            Crc5Coverage::ScratchRangeHypothesisA.byte_range(),
            Some((5, 11))
        );
        assert_eq!(Crc5Coverage::TransmittedZeroHypothesisC.byte_range(), None);
    }

    // ── Registers / topology constants ──────────────────────────────────────

    #[test]
    fn register_map_and_ticket_masks_match_the_contract() {
        assert_eq!(REG_BAUD_DIVIDER, 0x01);
        assert_eq!(REG_INIT_BROADCAST, 0x02);
        assert_eq!(INIT_BROADCAST_VALUE, 0x00FF_000F);
        assert_eq!(REG_PLL0, 0x03);
        assert_eq!(REG_PLL1, 0x04);
        assert_eq!(REG_CHIP_DETECT, 0x10);
        assert_eq!(CHIP_DETECT_ARG, 0x4BF);
        assert_eq!(REG_SOFT_RESET, 0x15);
        assert_eq!(REG_PLL_SELECT, 0x22);
        // HIGH-bits convention — do not invert by analogy with BM13xx.
        assert_eq!(TICKET_MASK_DEFAULT, 0xFFFE_0000);
        assert_eq!(TICKET_MASK_DC08, 0xFFFF_C000);
        assert_eq!(baud_divider_code(115_200), Some(0x1A));
        assert_eq!(baud_divider_code(25_000_000), Some(0x01));
        assert_eq!(baud_divider_code(1_000_000), None);
        // PLL envelope.
        assert_eq!(PLL_REF_MHZ, 25);
        assert_eq!(
            (*PLL_FBDIV_RANGE.start(), *PLL_FBDIV_RANGE.end()),
            (80, 480)
        );
        assert_eq!(
            (*PLL_VCO_MHZ_RANGE.start(), *PLL_VCO_MHZ_RANGE.end()),
            (4000, 8000)
        );
    }

    #[test]
    fn address_interval_matches_the_registered_dc0x_boards() {
        assert_eq!(address_interval(2), Some(0x80), "DC02");
        assert_eq!(address_interval(4), Some(0x40), "DC04");
        assert_eq!(address_interval(6), Some(0x2A), "DC06");
        assert_eq!(address_interval(8), Some(0x20), "DC08 (not registered)");
        assert_eq!(address_interval(1), None, "1-chip chain skips addressing");
        assert_eq!(address_interval(0), None);
    }

    // ── Fail-closed posture ─────────────────────────────────────────────────

    // R2 is CLOSED. This test previously asserted `== PayloadTransform::Unresolved`,
    // which encoded "we have not decoded this yet" — now false. Per the rule that
    // refusal tests are edited with INTENT rather than deleted, it is replaced by a
    // pin on the newly proven value PLUS the still-closed driver posture, so the
    // fail-closed guarantee cannot silently regress alongside the knowledge gain.
    #[test]
    fn payload_final_transform_is_resolved_but_the_driver_still_refuses() {
        assert_eq!(
            WORK_PAYLOAD_FINAL_TRANSFORM,
            PayloadTransform::WholeBufferByteReverse,
            "R2 resolved 2026-08-02 from the vendor helper at IROM 0x420fddd0 \
             (in-place head/tail byte swap, len>>1 iterations, l8ui/s8i only); \
             byte-identical in 5 of 5 relevant miner images"
        );

        // Resolving R2 must NOT open the work path: R1/R3 are open and the rail
        // is RailBringup::NoActuator.
        use crate::AsicDriver;
        let mut d = Lt0051::new(SerialPort::new());
        assert!(
            d.send_work(&test_job()).is_err(),
            "R2 closing must not energize the work path"
        );
        assert!(d.init(2300.0, 2, 256.0).is_err());
    }

    #[test]
    fn the_final_transform_reverses_the_whole_buffer_not_each_word() {
        // A buffer whose value equals its index makes both hypotheses distinguishable.
        let mut whole: [u8; WORK_PAYLOAD_LEN] = core::array::from_fn(|i| i as u8);
        apply_payload_final_transform(&mut whole, PayloadTransform::WholeBufferByteReverse)
            .expect("resolved transform applies");
        assert_eq!(whole[0], 75, "byte 0 must come from the tail");
        assert_eq!(whole[75], 0);
        assert_eq!(whole[1], 74);

        let mut per_word: [u8; WORK_PAYLOAD_LEN] = core::array::from_fn(|i| i as u8);
        apply_payload_final_transform(&mut per_word, PayloadTransform::PerWordByteReverse)
            .expect("applies");
        assert_eq!(
            per_word[0], 3,
            "word-wise would only reverse within 4 bytes"
        );
        assert_ne!(
            whole, per_word,
            "the two hypotheses must be distinguishable, otherwise the pin is vacuous"
        );
    }

    #[test]
    fn an_unresolved_transform_refuses_and_does_not_mutate() {
        let original: [u8; WORK_PAYLOAD_LEN] = core::array::from_fn(|i| i as u8);
        let mut buf = original;
        assert!(
            apply_payload_final_transform(&mut buf, PayloadTransform::Unresolved).is_err(),
            "an unresolved transform must refuse, never degrade to a no-op"
        );
        assert_eq!(
            buf, original,
            "a refused transform must leave the buffer alone"
        );
    }

    #[test]
    fn wire_payload_puts_nbits_first_and_version_last() {
        // Derived consequence of BE scalar stores + whole-buffer reversal (§4.3).
        // Flagged in-file as derived, not capture-confirmed.
        let job = test_job();
        let wire = assemble_scrypt_payload_wire(&job).expect("R2 is resolved");
        assert_eq!(
            &wire[0x00..0x04],
            &job.nbits.to_le_bytes(),
            "nBits lands first, little-endian"
        );
        assert_eq!(&wire[0x04..0x08], &job.ntime.to_le_bytes());
        assert_eq!(
            &wire[0x48..0x4C],
            &job.version.to_le_bytes(),
            "version lands last, little-endian"
        );

        // And the whole thing is exactly the pre-transform buffer reversed.
        let mut expected = assemble_scrypt_payload(&job);
        expected.reverse();
        assert_eq!(wire, expected);
    }

    #[test]
    fn every_driver_method_refuses() {
        use crate::AsicDriver;
        let mut d = Lt0051::new(SerialPort::new());
        assert!(d.init(2300.0, 2, 256.0).is_err());
        assert!(d.send_work(&test_job()).is_err());
        assert!(d.process_work(&[0u8; 11]).is_err());
        assert!(d.set_frequency(2300.0).is_err());
        assert!(d.set_version_mask(0x1FFF_E000).is_err());
        assert!(d.read_registers().is_err());
        assert!(d.read_responses(10).is_err());
        assert!(d.set_difficulty(1024.0).is_err());
        assert!(d.set_max_baud().is_err());
        assert_eq!(d.chip_count(), 0);
    }

    #[test]
    fn job_id_counter_advances_through_the_driver() {
        let mut d = Lt0051::new(SerialPort::new());
        assert_eq!(d.take_job_id(), 0);
        assert_eq!(d.take_job_id(), 1);
        for _ in 0..125 {
            d.take_job_id();
        }
        assert_eq!(d.take_job_id(), 127);
        assert_eq!(d.take_job_id(), 0, "wraps at 127");
    }
}
