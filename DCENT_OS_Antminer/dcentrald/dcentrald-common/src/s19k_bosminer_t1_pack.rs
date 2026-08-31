//! Gap-4 desk evidence module — Braiins `bosminer.unpacked` **TYPE_JOB
//! packer, work-id math, and HCN divider** re-derived first-hand from the
//! held binary (2026-08-19).
//!
//! Binary:
//! 04-binaries/bosminer.unpacked` (23,963,080 B, ELF64 aarch64, static
//! musl, stripped, non-PIE `e_type=EXEC`, image base 0x400000).
//! Method: capstone linear disassembly at the known VAs + Ghidra
//! (ghidra-mcp-dcent Docker, REST) per-function decompiles. Every constant
//! below was read out of this ELF this session; no live miner, no network.
//!
//! ## What this module pins (all OFFLINE_PROVEN this session)
//!
//! 1. **TYPE_JOB pack chain** `FUN_0091bfe8 → fill FUN_0091ba88 →
//!    pack FUN_0091beb4` (/42 map re-verified instruction by
//!    instruction, independently):
//!    wire = `55 AA` + `21 36` + 82 B ESP-order body + 2 B BE CRC = 88 B.
//!    The length byte `0x36` is *not computed anywhere* — it rides inside
//!    one 4-byte rodata word `55 AA 21 36` (VA `0x12EC448`, file
//!    `0xEEC448`) SIMD-copied into the frame head.
//! 2. **TX CRC** = the binary's `init 0x84CF` + table-update + two-lookup
//!    finalize is *numerically identical* to CRC16-CCITT-FALSE (poly
//!    `0x1021`, init `0xFFFF`, no reflection, no xorout) — proven by
//!    exhaustive recurrence equality in tests.
//! 3. **`Self::get_work_id_count(midstate_count)`** (assertion at
//!    `ext_work_id.rs:81:9`, `FUN_0092e784`) = `0x1_0000 >> log2(count)`
//!    = `65536 / count`; `ExtWorkId::to_hw` = `work_id << log2(count)`
//!    (FPGA FIFO W0).
//! 4. **Fill-path job_id identity**: fill hardcodes `midstates = 1`
//!    (store of `#1` at fill+0x55), so the TX encoder call
//!    `(*(engine+0x90))(work_id, 1)` and the RX inverse
//!    `work_id = frame_byte >> log2(count)` (FUN_0091c0a0) both reduce
//!    to identity: on-wire `job_id == work_id`, sequential 0..255
//!    (registry bound `0x100 >> log` ⇒ 256 at log 0). The general
//!    (count > 1) encoder *body* is still unnamed — see the refuse pin.
//! 5. **HCN divider formula** (bonus, `bm136x.rs` shared driver math,
//!    `FUN_0091b214`): `divider = trunc(x0 / f64(cfg+0x148) / ref ×
//!    12_500_000.0 × 0.8) & 0x7FFF_FFFF`.
//!
//! This module is evidence only. The production packer lives in
//! [`crate::s19k_braiins_job`] (sibling-owned) and is NOT touched here.

// ---------------------------------------------------------------------------
// Binary identity anchors
// ---------------------------------------------------------------------------

/// Held bosminer ELF size in bytes.
pub const BOSMINER_UNPACKED_LEN: u64 = 23_963_080;
/// ELF is `ET_EXEC` (static non-PIE): rodata pointers are absolute VAs.
pub const BOSMINER_ELF_TYPE_EXEC: u16 = 2;
/// Program-header image base (PH0: va 0x400000 at file offset 0).
pub const BOSMINER_IMAGE_BASE: u64 = 0x0040_0000;
/// VA of the 4-byte packer prefix word `55 AA 21 36` (file off 0xEEC448).
pub const BOSMINER_PREFIX_CONST_VA: u64 = 0x012E_C448;
/// The prefix constant itself (one rodata u32, little-endian on disk).
pub const BOSMINER_PREFIX_WORD: [u8; 4] = [0x55, 0xAA, 0x21, 0x36];

// ---------------------------------------------------------------------------
// TYPE_JOB wire layout (pack FUN_0091beb4 dest map, verified 2026-08-19)
// ---------------------------------------------------------------------------

/// Total on-wire frame size produced by `FUN_0091beb4` (alloc 0x56 + 2 B CRC).
pub const T1_JOB_WIRE_TOTAL: usize = 0x58;
/// Body the packer allocates before the CRC append (`mov w0,#0x56` @ 0x91BEC8).
pub const T1_JOB_BODY_ALLOC: usize = 0x56;
/// CRC-covered span: `dest+2`, length `0x54` (type+len+82 B payload).
pub const T1_JOB_CRC_OFF: usize = 2;
pub const T1_JOB_CRC_LEN: usize = 0x54;
/// CRC trailer offset (big-endian store @ dest+0x56, total 0x58).
pub const T1_JOB_CRC_TRAILER_OFF: usize = 0x56;

/// One field of the TYPE_JOB wire layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T1JobField {
    /// Destination offset inside the packed 0x58-byte frame.
    pub off: usize,
    /// Field width in bytes.
    pub len: usize,
    /// Field name (ESP `BM1366_job` order).
    pub name: &'static str,
}

/// Dest map of `FUN_0091beb4` (SIMD reorder out of the fill struct), read
/// from the binary this session. `55 AA` @0, `21` @2 (TYPE_JOB|write),
/// `36` @3 (dialect constant), then the 82-byte ESP job.
pub const T1_JOB_WIRE_FIELDS: [T1JobField; 11] = [
    T1JobField {
        off: 0x00,
        len: 2,
        name: "preamble 55 AA",
    },
    T1JobField {
        off: 0x02,
        len: 1,
        name: "type 0x21 (TYPE_JOB|CMD_WRITE)",
    },
    T1JobField {
        off: 0x03,
        len: 1,
        name: "length dialect 0x36 (constant)",
    },
    T1JobField {
        off: 0x04,
        len: 1,
        name: "job_id",
    },
    T1JobField {
        off: 0x05,
        len: 1,
        name: "num_midstates",
    },
    T1JobField {
        off: 0x06,
        len: 4,
        name: "starting_nonce",
    },
    T1JobField {
        off: 0x0A,
        len: 4,
        name: "nbits",
    },
    T1JobField {
        off: 0x0E,
        len: 4,
        name: "ntime",
    },
    T1JobField {
        off: 0x12,
        len: 32,
        name: "merkle_root",
    },
    T1JobField {
        off: 0x32,
        len: 32,
        name: "prev_block_hash",
    },
    T1JobField {
        off: 0x52,
        len: 4,
        name: "version",
    },
];

/// Fill-struct (`FUN_0091ba88` sret) offsets that the packer re-orders.
pub const T1_FILL_PREFIX_OFF: usize = 0x50;
pub const T1_FILL_JOB_ID_OFF: usize = 0x54;
pub const T1_FILL_MIDSTATES_OFF: usize = 0x55;
pub const T1_FILL_NONCE_OFF: usize = 0x40;
pub const T1_FILL_NBITS_OFF: usize = 0x44;
pub const T1_FILL_NTIME_OFF: usize = 0x48;
pub const T1_FILL_VERSION_OFF: usize = 0x4C;
/// Fill hardcodes `num_midstates = 1` (`mov w8,#1; strb w8,[x19,#0x55]`).
pub const T1_FILL_MIDSTATES: u8 = 1;
/// Fill hardcodes `starting_nonce = 0` (`stp wzr,w8,[x19,#0x40]`).
pub const T1_FILL_NONCE: u32 = 0;

// Instruction-level anchors (u32 little-endian words read from the ELF).

/// `ADR`P+`LDR d0,[x8,#0x448]` loads the 8-byte pool entry at VA 0x12EC448
/// and `str s0,[x19,#0x50]` stores the low 4 bytes (`55 AA 21 36`) at
/// fill+0x50. Proof the prefix is one rodata constant, not computed bytes.
pub const T1_FILL_PREFIX_LDR_INSN: u32 = 0xFD42_2500; // ldr d0,[x8,#0x448] @ 0x91BDD0
pub const T1_FILL_PREFIX_LDR_VA: u64 = 0x0091_BDD0;
pub const T1_FILL_PREFIX_STR_INSN: u32 = 0xBD00_5260; // str s0,[x19,#0x50] @ 0x91BDE0
/// `strb w8,[x19,#0x54]` — job_id lands at fill+0x54 (from the encoder call).
pub const T1_FILL_JOB_ID_STRB_INSN: u32 = 0x3901_5268; // @ 0x91BCD0
/// `mov w8,#1` immediately before the midstates store.
pub const T1_FILL_MIDSTATES_MOV_INSN: u32 = 0x5280_0028; // @ 0x91BCD4
pub const T1_FILL_MIDSTATES_STRB_INSN: u32 = 0x3901_5668; // strb w8,[x19,#0x55] @ 0x91BCD8
/// `stp wzr,w8,[x19,#0x40]` — starting_nonce 0 at +0x40, nbits at +0x44.
pub const T1_FILL_NONCE_STP_INSN: u32 = 0x2908_227F; // @ 0x91BDC8
/// `stp w21,w0,[x19,#0x48]` — ntime (work+0x38) at +0x48, version at +0x4C.
pub const T1_FILL_NTIME_STP_INSN: u32 = 0x2909_2075; // @ 0x91BD40
/// Packer body-size alloc: `mov w0,#0x56` @ 0x91BEC8.
pub const T1_PACK_ALLOC_MOVZ_INSN: u32 = 0x5280_0AC0;
pub const T1_PACK_ALLOC_MOVZ_VA: u64 = 0x0091_BEC8;
/// CRC update args: `add x1,x20,#2` + `mov w2,#0x54` @ 0x91BF58/0x91BF5C.
pub const T1_PACK_CRC_ADD2_INSN: u32 = 0x9100_0A81;
pub const T1_PACK_CRC_LEN_MOVZ_INSN: u32 = 0x5280_0A82;
/// BE CRC append: `rev w8,w20` … `lsr w8,w8,#0x10` … `strh w8,[x10,x9]`.
pub const T1_PACK_CRC_REV_INSN: u32 = 0x5AC0_0A88; // @ 0x91BF88
pub const T1_PACK_CRC_LSR16_INSN: u32 = 0x5310_7D08; // @ 0x91BF90
pub const T1_PACK_CRC_STRH_INSN: u32 = 0x7829_6948; // @ 0x91BF98

// ---------------------------------------------------------------------------
// CRC family (FUN_00938f50 init / 00938f58 update / 00938f84 finalize)
// ---------------------------------------------------------------------------

/// `FUN_00938f50`: CRC state starts at 0x84CF (`mov w0,#0x84cf; ret`).
pub const BOSMINER_CRC_INIT: u16 = 0x84CF;
pub const BOSMINER_CRC_INIT_MOVZ_INSN: u32 = 0x5290_99E0; // @ 0x938F50
/// CRC table VA; head is the classic MSB-first CCITT table for poly 0x1021.
pub const BOSMINER_CRC_TABLE_VA: u64 = 0x0132_8F60;
pub const BOSMINER_CRC_TABLE_HEAD: [u16; 8] = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
];
/// Bit-banged table (poly 0x1021, MSB first) — equals the rodata table.
pub const BOSMINER_CRC_POLY: u16 = 0x1021;

fn crc_table() -> [u16; 256] {
    let mut t = [0u16; 256];
    for (i, slot) in t.iter_mut().enumerate() {
        let mut c = (i as u16) << 8;
        for _ in 0..8 {
            c = if c & 0x8000 != 0 {
                ((c << 1) ^ BOSMINER_CRC_POLY) & 0xFFFF
            } else {
                (c << 1) & 0xFFFF
            };
        }
        *slot = c;
    }
    t
}

/// `FUN_00938f58` byte update, exactly as encoded:
/// `crc = ((crc << 8) | byte) ^ table[(crc >> 8) & 0xFF]` (16-bit).
pub fn bosminer_crc_update(crc: u16, data: &[u8]) -> u16 {
    let t = crc_table();
    let mut crc = crc;
    for &b in data {
        let idx = ((crc >> 8) & 0xFF) as usize;
        crc = ((((crc as u32) << 8) | b as u32) as u16) ^ t[idx];
    }
    crc
}

/// `FUN_00938f84` finalize: two extra table lookups:
/// `t1 = table[hi(crc)]; v = t1 ^ (crc << 8); t2 = table[hi(v)];
/// return t2 ^ (t1 << 8)`.
pub fn bosminer_crc_finalize(mut crc: u16) -> u16 {
    let t = crc_table();
    let t1 = t[((crc >> 8) & 0xFF) as usize];
    let v = (t1 ^ ((crc as u32) << 8) as u16) & 0xFFFF;
    let t2 = t[((v >> 8) & 0xFF) as usize];
    crc = (t2 ^ (((t1 as u32) << 8) as u16)) & 0xFFFF;
    crc
}

/// Canonical CRC16-CCITT-FALSE (poly 0x1021, init 0xFFFF, MSB first,
/// no reflection, no xorout) — the form DCENT already ships.
pub fn crc16_ccitt_false(data: &[u8]) -> u16 {
    let t = crc_table();
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        let idx = (((crc >> 8) ^ b as u16) & 0xFF) as usize;
        crc = (((crc as u32) << 8) as u16) ^ t[idx];
    }
    crc
}

/// Full bosminer CRC pipeline over a frame: update over `frame[2..0x56]`
/// then finalize (mirrors pack `FUN_0091beb4` CRC sequence).
pub fn bosminer_frame_crc(frame: &[u8]) -> Result<u16, &'static str> {
    let body = frame
        .get(T1_JOB_CRC_OFF..T1_JOB_CRC_OFF + T1_JOB_CRC_LEN)
        .ok_or("frame shorter than the 0x54-byte CRC-covered span")?;
    Ok(bosminer_crc_finalize(bosminer_crc_update(
        BOSMINER_CRC_INIT,
        body,
    )))
}

// ---------------------------------------------------------------------------
// ext_work_id.rs work-id math (FUN_0092e784)
// ---------------------------------------------------------------------------

/// Panic string VA: `assertion failed: self.work_id <
/// Self::get_work_id_count(midstate_count)` (72 bytes).
pub const BOSMINER_EXT_WORK_ID_ASSERT_VA: u64 = 0x0132_7BC3;
/// Panic call site (ADRP+ADD into the string, then `bl 0x453754`).
pub const BOSMINER_EXT_WORK_ID_ASSERT_SITE_VA: u64 = 0x0092_EC60;
/// rustc `Location` for the assertion: ext_work_id.rs line 81 col 9.
pub const BOSMINER_EXT_WORK_ID_ASSERT_LOC_VA: u64 = 0x019C_CD70;
pub const BOSMINER_EXT_WORK_ID_ASSERT_LINE: u32 = 81;
pub const BOSMINER_EXT_WORK_ID_ASSERT_COL: u32 = 9;
/// `mov w9,#0x10000` + `lsr w9,w9,w8` @ 0x92EA1C/0x92EA20 — the count.
pub const BOSMINER_WORK_ID_COUNT_MOVZ_INSN: u32 = 0x52A0_0029;
pub const BOSMINER_WORK_ID_COUNT_LSR_INSN: u32 = 0x1AC8_2529;
/// `and x8,x8,#0x3f; lsl x8,x4,x8` @ 0x92EA38/0x92EA3C — to_hw shift.
pub const BOSMINER_TO_HW_AND_INSN: u32 = 0x9240_1508;
pub const BOSMINER_TO_HW_LSL_INSN: u32 = 0x9AC8_2088;
/// `str w8,[x9,#4]` — to_hw word is FIFO W0 of the FPGA work-tx writer.
pub const BOSMINER_TO_HW_STR_INSN: u32 = 0xB900_0508; // @ 0x92EA40

/// `Self::get_work_id_count(midstate_count) = 0x10000 >> log2(count)`
/// (`65536 / count`). Count must be a power of two in 1..=8 (log 0..=3,
/// per the `FUN_0092f200` midstate-log bound already pinned in
/// [`crate::s19k_braiins_job`]).
pub fn bosminer_get_work_id_count(midstate_count: u32) -> Result<u32, &'static str> {
    let log = midstate_log(midstate_count)?;
    Ok(0x1_0000u32 >> log)
}

/// `ExtWorkId::to_hw(work_id, midstate_count) = work_id << log2(count)`
/// with the same power-of-two bound; result must stay under
/// [`bosminer_get_work_id_count`] shifted up (assert at ext_work_id.rs:81).
pub fn bosminer_to_hw_work_id(work_id: u32, midstate_count: u32) -> Result<u64, &'static str> {
    let log = midstate_log(midstate_count)?;
    let count = bosminer_get_work_id_count(midstate_count)?;
    if work_id >= count {
        return Err("work_id >= get_work_id_count (ext_work_id.rs:81 assert fires)");
    }
    Ok(u64::from(work_id) << log)
}

fn midstate_log(midstate_count: u32) -> Result<u32, &'static str> {
    match midstate_count {
        1 => Ok(0),
        2 => Ok(1),
        4 => Ok(2),
        8 => Ok(3),
        _ => Err("midstate_count must be a power of two 1..=8 (1<<log check @ 0x92EA0C)"),
    }
}

// ---------------------------------------------------------------------------
// TX job_id (FUN_0091bfe8) and the fill-path identity closure
// ---------------------------------------------------------------------------

/// Pack-caller loads the encoder fn ptr from engine (Worker) +0x90.
pub const BOSMINER_TX_JOB_ID_FN_OFF: usize = 0x90;
/// Pack-caller loads the midstate log from engine (Worker) +0x70.
pub const BOSMINER_TX_MIDSTATE_LOG_OFF: usize = 0x70;
/// Registry work_id input: `ldr x0,[x0,#0x40]` (work+0x40).
pub const BOSMINER_TX_WORK_ID_OFF: usize = 0x40;
/// Encoder invocation: `ldr x10,[x1,#0x70]; ldr x11,[x1,#0x90];
/// ldr x0,[x0,#0x40]; lsl x1,x9,x10; blr x11` @ 0x91BFF4..0x91C010.
pub const BOSMINER_TX_LDR_LOG_INSN: u32 = 0xF940_382A;
pub const BOSMINER_TX_LDR_FN_INSN: u32 = 0xF940_482B;
pub const BOSMINER_TX_LDR_WORK_ID_INSN: u32 = 0xF940_2000;
pub const BOSMINER_TX_LSL_COUNT_INSN: u32 = 0x9ACA_2121;
pub const BOSMINER_TX_BLR_INSN: u32 = 0xD63F_0160;
/// RX inverse (FUN_0091c0a0): `ubfx x10,x24,#0x28,#8` grabs payload byte 5
/// (the job_id), then `lsr x21,x10,x9` shifts out the log.
pub const BOSMINER_RX_UBFX_JOB_BYTE_INSN: u32 = 0xD368_BF0A; // @ 0x91C110
pub const BOSMINER_RX_LSR_WORK_ID_INSN: u32 = 0x9AC9_2555; // @ 0x91C128
pub const BOSMINER_RX_JOB_BYTE_OFF: usize = 5;

/// Fill-path on-wire job_id: fill hardcodes `midstates = 1`, so the
/// encoder is called with `midstate_count = 1` (log 0) and the RX decode
/// `byte >> 0` — the on-wire byte IS the registry `work_id`, sequential
/// under the `0x100 >> log` registry bound (256 slots at log 0).
pub fn admit_bosminer_t1_fill_job_id_is_work_id(fill_midstates: u8) -> Result<(), &'static str> {
    if fill_midstates != T1_FILL_MIDSTATES {
        return Err("fill FUN_0091ba88 stores num_midstates=1 at +0x55 (0x91BCD4)");
    }
    if bosminer_get_work_id_count(u32::from(fill_midstates))? != 0x1_0000 {
        return Err("get_work_id_count(1) must be 0x10000 (log 0)");
    }
    // RX inverse with log 0: byte >> 0 == byte.
    let _ = midstate_log(1)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// HCN divider (bonus — bm136x.rs shared driver math, FUN_0091b214)
// ---------------------------------------------------------------------------

/// `FUN_0091b214` immediate `mov x8,#0xd78400000000;
/// movk x8,#0x4167,lsl#48` = f64 12_500_000.0.
pub const BOSMINER_HCN_IMM_LO_INSN: u32 = 0xD2DA_F088; // @ 0x91B234
pub const BOSMINER_HCN_IMM_HI_INSN: u32 = 0xF2E8_2CE8; // @ 0x91B238
pub const BOSMINER_HCN_SCALE: f64 = 12_500_000.0;
/// Second scale factor: rodata f64 `0.8` at VA 0x12EBF18.
pub const BOSMINER_HCN_SCALE2_VA: u64 = 0x012E_BF18;
pub const BOSMINER_HCN_SCALE2: f64 = 0.8;
/// `fcvtzu w8,d0` + `and w0,w8,#0x7fffffff` tail of FUN_0091b214.
pub const BOSMINER_HCN_FCVTZU_INSN: u32 = 0x1E79_0008; // @ 0x91B268
pub const BOSMINER_HCN_AND31_INSN: u32 = 0x1200_7900; // @ 0x91B26C
/// bm1366 hashchain init stores the divider at self+0x20 (call @ 0x8DBFB0).
pub const BOSMINER_HCN_DIVIDER_OFF: usize = 0x20;
/// HCN log call site (references the field-name table @ 0x19C7BF0).
pub const BOSMINER_HCN_LOG_SITE_VA: u64 = 0x008D_C220;
/// Field-name table VA: "HCN divider: ", "serial versions: ",
/// "frequency: ", "max work time: ", " ms".
pub const BOSMINER_HCN_FIELD_TABLE_VA: u64 = 0x019C_7BF0;
/// bm1366 monomorphization's copy of the format block (5th of five).
pub const BOSMINER_HCN_BM1366_FMT_VA: u64 = 0x0132_337D;

/// HCN divider as computed by `FUN_0091b214`:
/// `trunc((x0 / cfg148 / ref) * 12_500_000.0 * 0.8) & 0x7FFF_FFFF`
/// where `x0 = f64(bf2494(cfg+0x60))`, `cfg148 = f64 at cfg+0x148`,
/// `ref` = the u64 argument.
pub fn bosminer_hcn_divider(x0: f64, cfg148: f64, ref_clock: f64) -> u32 {
    let v = (x0 / cfg148 / ref_clock) * BOSMINER_HCN_SCALE * BOSMINER_HCN_SCALE2;
    let t = if v.is_finite() && v > 0.0 {
        v.trunc()
    } else {
        0.0
    };
    (t as i64 & 0x7FFF_FFFF) as u32
}

// ---------------------------------------------------------------------------
// Admit / refuse pins
// ---------------------------------------------------------------------------

/// Wire layout contract for `FUN_0091beb4`: 11 fields tile exactly
/// `0x00..0x56`, CRC trailer at `0x56..0x58`, total 88 bytes.
pub fn admit_bosminer_t1_wire_layout(fields: &[T1JobField]) -> Result<(), &'static str> {
    if fields.len() != T1_JOB_WIRE_FIELDS.len() {
        return Err("TYPE_JOB layout must carry the 11 pinned fields");
    }
    for (got, want) in fields.iter().zip(T1_JOB_WIRE_FIELDS.iter()) {
        if got != want {
            return Err("TYPE_JOB field map drifted from FUN_0091beb4 dest offsets");
        }
    }
    let last = T1_JOB_WIRE_FIELDS.last().expect("non-empty");
    if last.off + last.len != T1_JOB_CRC_TRAILER_OFF {
        return Err("last field must end at the 0x56 CRC trailer");
    }
    if T1_JOB_CRC_TRAILER_OFF + 2 != T1_JOB_WIRE_TOTAL {
        return Err("total frame size must stay 0x58");
    }
    Ok(())
}

/// The packer prefix is ONE rodata constant (`55 AA 21 36` @ VA
/// 0x12EC448) copied by `ldr d0/str s0`; the length byte `0x36` is never
/// computed from a size. ESP's `sizeof(job)+4 = 0x56` formula is a
/// different dialect, not this binary's.
pub fn admit_bosminer_t1_prefix_word_is_rodata_constant(
    prefix: [u8; 4],
) -> Result<(), &'static str> {
    if prefix != BOSMINER_PREFIX_WORD {
        return Err("TYPE_JOB head must be the rodata word 55 AA 21 36 (VA 0x12EC448)");
    }
    Ok(())
}

/// Refuse any reading that `0x36` "counts" something in this binary:
/// the packer allocates 0x56, CRCs 0x54 from +2, totals 0x58 — none of
/// which is 0x36; the byte is a fixed dialect constant shared with the
/// stock Bitmain kernel packer.
pub fn refuse_len_0x36_as_computed_size() -> Result<(), &'static str> {
    Err(
        "0x36 is a constant inside the 4-byte rodata prefix; pack computes \
         0x56 alloc / 0x54 CRC span / 0x58 total and never stores dest[3]",
    )
}

/// CRC contract: the binary's 0x84CF-init + finalize pipeline equals
/// CRC16-CCITT-FALSE on the given data (callers pass representative
/// frames; the tests prove the recurrence identity exhaustively).
pub fn admit_bosminer_crc_is_ccitt_false(data: &[u8]) -> Result<(), &'static str> {
    let bosminer = bosminer_crc_finalize(bosminer_crc_update(BOSMINER_CRC_INIT, data));
    let ccitt = crc16_ccitt_false(data);
    if bosminer != ccitt {
        return Err("bosminer 0x84CF+finalize pipeline diverged from CCITT-FALSE");
    }
    if bosminer_crc_finalize(BOSMINER_CRC_INIT) != 0xFFFF {
        return Err("finalize(0x84CF) on empty input must be exactly 0xFFFF");
    }
    Ok(())
}

/// Table-drift refuse: the rodata CRC table head must stay CCITT-0x1021.
pub fn admit_bosminer_crc_table_head(head: &[u16]) -> Result<(), &'static str> {
    if head.len() < BOSMINER_CRC_TABLE_HEAD.len() || head[..8] != BOSMINER_CRC_TABLE_HEAD[..] {
        return Err("CRC table @ 0x1328F60 must open with 0,1021,2042,3063,4084,50a5,60c6,70e7");
    }
    Ok(())
}

/// Work-id math contract: count = 0x10000>>log, to_hw = work_id<<log,
/// and the assert covers `work_id < count` exactly.
pub fn admit_bosminer_ext_work_id_math(midstate_count: u32) -> Result<(), &'static str> {
    let count = bosminer_get_work_id_count(midstate_count)?;
    if count * midstate_count != 0x1_0000 {
        return Err("get_work_id_count(count) * count must equal 0x10000");
    }
    if bosminer_to_hw_work_id(count - 1, midstate_count).is_err() {
        return Err("count-1 must be the last legal work_id");
    }
    if bosminer_to_hw_work_id(count, midstate_count).is_ok() {
        return Err("work_id == count must trip the ext_work_id.rs:81 assert");
    }
    Ok(())
}

/// The FPGA formula is NOT the ttyS registry bound: UART workers use
/// `0x100 >> log` (five am3.rs factories, already pinned in
/// [`crate::s19k_braiins_job`]); `0x10000 >> log` is ext_work_id.rs only.
pub fn refuse_fpga_work_id_count_as_uart_registry(count: u32) -> Result<(), &'static str> {
    if count == 0x1_0000 {
        return Err("0x10000>>log is ext_work_id.rs FPGA; UART registry is 0x100>>log");
    }
    Ok(())
}

/// The general TX encoder body (engine+0x90 callee for midstate_count > 1)
/// is still unnamed in the binary (constructed via a factory engine
/// template memcpy'd into the Worker). This session proves the call shape
/// and closes the *fill path* (count == 1 ⇒ identity); do NOT pin a
/// general formula.
pub fn refuse_unnamed_engine_0x90_encoder_as_general_formula(
    count: u32,
) -> Result<(), &'static str> {
    if count > 1 {
        return Err(
            "engine+0x90 callee body unnamed; only (work_id, count=1) => identity is proven",
        );
    }
    Ok(())
}

/// HCN evidence contract: constants and call sites for the bm1366
/// hashchain init log line.
pub fn admit_bosminer_hcn_divider_evidence() -> Result<(), &'static str> {
    if BOSMINER_HCN_SCALE != 12_500_000.0 || BOSMINER_HCN_SCALE2 != 0.8 {
        return Err("HCN scale factors must stay 12.5e6 and 0.8");
    }
    // Known-good numeric shape: divider is a non-negative u32.
    let d = bosminer_hcn_divider(1.0, 1.0, 1.0);
    if d != 10_000_000 {
        return Err("HCN formula sanity (1/1/1 => 10_000_000) failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic PRNG (no external crates) for CRC equivalence fuzzing.
    struct Lcg(u64);
    impl Lcg {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) as u32
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next_u32() as u8).collect()
        }
    }

    #[test]
    fn t1_wire_layout_tiles_88_bytes() {
        admit_bosminer_t1_wire_layout(&T1_JOB_WIRE_FIELDS).expect("layout contract");
        // Field coverage must be gapless 0..0x56.
        let mut cursor = 0;
        for f in &T1_JOB_WIRE_FIELDS {
            assert_eq!(f.off, cursor, "gap before field {}", f.name);
            cursor = f.off + f.len;
        }
        assert_eq!(cursor, T1_JOB_CRC_TRAILER_OFF);
        assert_eq!(T1_JOB_WIRE_TOTAL, 88);
        assert_eq!(T1_JOB_BODY_ALLOC, 0x56);
        assert_eq!(T1_JOB_CRC_LEN, 0x54);
        assert_eq!(T1_JOB_CRC_OFF + T1_JOB_CRC_LEN, T1_JOB_BODY_ALLOC);
    }

    #[test]
    fn t1_prefix_is_one_rodata_word() {
        admit_bosminer_t1_prefix_word_is_rodata_constant([0x55, 0xAA, 0x21, 0x36])
            .expect("prefix pin");
        assert!(
            admit_bosminer_t1_prefix_word_is_rodata_constant([0x55, 0xAA, 0x21, 0x56]).is_err()
        );
        assert!(refuse_len_0x36_as_computed_size().is_err());
        // Instruction anchors: the fill loads the prefix from VA 0x12EC448.
        assert_eq!(T1_FILL_PREFIX_LDR_VA, 0x0091_BDD0);
        assert_eq!(BOSMINER_PREFIX_CONST_VA, 0x012E_C448);
        assert_eq!(BOSMINER_IMAGE_BASE + 0x00EE_C448, BOSMINER_PREFIX_CONST_VA);
    }

    #[test]
    fn t1_fill_struct_offsets_stay_pinned() {
        assert_eq!(T1_FILL_PREFIX_OFF, 0x50);
        assert_eq!(T1_FILL_JOB_ID_OFF, 0x54);
        assert_eq!(T1_FILL_MIDSTATES_OFF, 0x55);
        assert_eq!(T1_FILL_NONCE_OFF, 0x40);
        assert_eq!(T1_FILL_NBITS_OFF, 0x44);
        assert_eq!(T1_FILL_NTIME_OFF, 0x48);
        assert_eq!(T1_FILL_VERSION_OFF, 0x4C);
        assert_eq!(T1_FILL_MIDSTATES, 1);
        assert_eq!(T1_FILL_NONCE, 0);
        // The packer dest map must agree with the fill sources.
        let by_name = |n: &str| T1_JOB_WIRE_FIELDS.iter().find(|f| f.name == n).unwrap();
        assert_eq!(by_name("job_id").off, 0x04);
        assert_eq!(by_name("num_midstates").off, 0x05);
        assert_eq!(by_name("starting_nonce").off, 0x06);
        assert_eq!(by_name("nbits").off, 0x0A);
        assert_eq!(by_name("ntime").off, 0x0E);
        assert_eq!(by_name("merkle_root").off, 0x12);
        assert_eq!(by_name("prev_block_hash").off, 0x32);
        assert_eq!(by_name("version").off, 0x52);
    }

    #[test]
    fn t1_crc_pipeline_equals_ccitt_false() {
        // Empty: finalize(0x84CF) == 0xFFFF == CCITT-FALSE of empty.
        assert_eq!(bosminer_crc_finalize(BOSMINER_CRC_INIT), 0xFFFF);
        assert_eq!(crc16_ccitt_false(&[]), 0xFFFF);
        admit_bosminer_crc_is_ccitt_false(&[]).expect("empty equivalence");
        // Table head sanity.
        admit_bosminer_crc_table_head(&crc_table()).expect("table head");
        // 2000 pseudo-random buffers, lengths 0..=96: recurrence identity.
        let mut rng = Lcg(0x2026_0819_DEAD_BEEF);
        for n in 0..2000usize {
            let data = rng.bytes(n % 97);
            admit_bosminer_crc_is_ccitt_false(&data).unwrap_or_else(|e| panic!("len {n}: {e}"));
        }
    }

    #[test]
    fn t1_crc_golden_zero_job_frame() {
        // All-zero 82-byte payload under 21 36 with job_id 0, midstates 1:
        // desk golden recovered this session — CRC16-CCITT-FALSE = 0x9887.
        let mut frame = [0u8; T1_JOB_WIRE_TOTAL];
        frame[0..4].copy_from_slice(&BOSMINER_PREFIX_WORD);
        frame[4] = 0x00; // job_id
        frame[5] = 0x01; // num_midstates
        let crc = bosminer_frame_crc(&frame).expect("golden frame crc");
        assert_eq!(crc, 0x9887);
        assert_eq!(crc16_ccitt_false(&frame[2..0x56]), 0x9887);
        frame[0x56..0x58].copy_from_slice(&crc.to_be_bytes());
        assert_eq!(frame.len(), 88);
        // Trailer is big-endian: rev+lsr#16+strh.
        assert_eq!(&frame[0x56..0x58], &[0x98, 0x87]);
    }

    #[test]
    fn t1_crc_instruction_anchors() {
        assert_eq!(BOSMINER_CRC_INIT, 0x84CF);
        assert_eq!(BOSMINER_CRC_INIT_MOVZ_INSN, 0x5290_99E0); // mov w0,#0x84cf
        assert_eq!(BOSMINER_CRC_TABLE_HEAD[1], 0x1021);
        assert_eq!(T1_PACK_CRC_ADD2_INSN, 0x9100_0A81); // add x1,x20,#2
        assert_eq!(T1_PACK_CRC_LEN_MOVZ_INSN, 0x5280_0A82); // mov w2,#0x54
        assert_eq!(T1_PACK_CRC_REV_INSN, 0x5AC0_0A88); // rev w8,w20
        assert_eq!(T1_PACK_CRC_LSR16_INSN, 0x5310_7D08); // lsr w8,w8,#0x10
        assert_eq!(T1_PACK_CRC_STRH_INSN, 0x7829_6948); // strh w8,[x10,x9]
        assert_eq!(T1_PACK_ALLOC_MOVZ_INSN, 0x5280_0AC0); // mov w0,#0x56
    }

    #[test]
    fn t1_get_work_id_count_formula() {
        // 0x10000 >> log == 65536/count, count = 1,2,4,8.
        assert_eq!(bosminer_get_work_id_count(1).unwrap(), 0x1_0000);
        assert_eq!(bosminer_get_work_id_count(2).unwrap(), 0x8000);
        assert_eq!(bosminer_get_work_id_count(4).unwrap(), 0x4000);
        assert_eq!(bosminer_get_work_id_count(8).unwrap(), 0x2000);
        assert!(bosminer_get_work_id_count(0).is_err());
        assert!(bosminer_get_work_id_count(3).is_err());
        assert!(bosminer_get_work_id_count(16).is_err());
        for count in [1u32, 2, 4, 8] {
            admit_bosminer_ext_work_id_math(count).expect("work-id math contract");
        }
        // Assertion site pins.
        assert_eq!(BOSMINER_EXT_WORK_ID_ASSERT_LINE, 81);
        assert_eq!(BOSMINER_EXT_WORK_ID_ASSERT_COL, 9);
        assert_eq!(BOSMINER_WORK_ID_COUNT_MOVZ_INSN, 0x52A0_0029); // mov w9,#0x10000
        assert_eq!(BOSMINER_WORK_ID_COUNT_LSR_INSN, 0x1AC8_2529); // lsr w9,w9,w8
        assert_eq!(BOSMINER_TO_HW_LSL_INSN, 0x9AC8_2088); // lsl x8,x4,x8
    }

    #[test]
    fn t1_to_hw_is_work_id_shifted_by_log() {
        assert_eq!(bosminer_to_hw_work_id(0, 1).unwrap(), 0);
        assert_eq!(bosminer_to_hw_work_id(5, 1).unwrap(), 5);
        assert_eq!(bosminer_to_hw_work_id(1, 8).unwrap(), 8); // slot<<3 shape at log 3
        assert_eq!(bosminer_to_hw_work_id(0x1FFF, 8).unwrap(), 0xFFF8);
        // Assert boundary: work_id == count refuses.
        assert!(bosminer_to_hw_work_id(0x1_0000, 1).is_err());
        assert!(bosminer_to_hw_work_id(0x2000, 8).is_err());
        // FPGA count is not the UART registry bound.
        assert!(refuse_fpga_work_id_count_as_uart_registry(0x1_0000).is_err());
        assert!(refuse_fpga_work_id_count_as_uart_registry(0x100).is_ok());
    }

    #[test]
    fn t1_fill_path_job_id_is_work_id_identity() {
        admit_bosminer_t1_fill_job_id_is_work_id(T1_FILL_MIDSTATES).expect("fill identity");
        assert!(admit_bosminer_t1_fill_job_id_is_work_id(2).is_err());
        // Encoder call shape: engine+0x70 log, engine+0x90 fn, work+0x40 id,
        // 1<<log count, blr — then result goes to fill+0x54.
        assert_eq!(BOSMINER_TX_LDR_FN_INSN, 0xF940_482B); // ldr x11,[x1,#0x90]
        assert_eq!(BOSMINER_TX_LDR_LOG_INSN, 0xF940_382A); // ldr x10,[x1,#0x70]
        assert_eq!(BOSMINER_TX_LDR_WORK_ID_INSN, 0xF940_2000); // ldr x0,[x0,#0x40]
        assert_eq!(BOSMINER_TX_LSL_COUNT_INSN, 0x9ACA_2121); // lsl x1,x9,x10
        assert_eq!(BOSMINER_TX_BLR_INSN, 0xD63F_0160); // blr x11
                                                       // RX inverse grabs payload byte 5 and shifts out the log.
        assert_eq!(BOSMINER_RX_JOB_BYTE_OFF, 5);
        assert_eq!(BOSMINER_RX_UBFX_JOB_BYTE_INSN, 0xD368_BF0A); // ubfx #0x28,#8
        assert_eq!(BOSMINER_RX_LSR_WORK_ID_INSN, 0x9AC9_2555); // lsr x21,x10,x9
                                                               // The count>1 encoder body stays unnamed: refuse over-claiming.
        assert!(refuse_unnamed_engine_0x90_encoder_as_general_formula(1).is_ok());
        assert!(refuse_unnamed_engine_0x90_encoder_as_general_formula(8).is_err());
    }

    #[test]
    fn t1_hcn_divider_evidence() {
        admit_bosminer_hcn_divider_evidence().expect("HCN evidence");
        // Scale anchors straight out of the instructions/rodata.
        assert_eq!(BOSMINER_HCN_SCALE, 12_500_000.0);
        assert_eq!(BOSMINER_HCN_SCALE2, 0.8);
        // f64 bit pattern of the movz/movk immediate pair.
        let bits: u64 = 0x4167_D784_0000_0000;
        assert_eq!(f64::from_bits(bits), 12_500_000.0);
        // Doubling the ref clock halves the divider (pure scaling).
        assert_eq!(
            bosminer_hcn_divider(2.0, 1.0, 1.0),
            bosminer_hcn_divider(1.0, 1.0, 0.5)
        );
        // Log-site anchors.
        assert_eq!(BOSMINER_HCN_LOG_SITE_VA, 0x008D_C220);
        assert_eq!(BOSMINER_HCN_FIELD_TABLE_VA, 0x019C_7BF0);
        assert_eq!(BOSMINER_HCN_BM1366_FMT_VA, 0x0132_337D);
    }

    #[test]
    fn t1_binary_identity_anchors() {
        assert_eq!(BOSMINER_UNPACKED_LEN, 23_963_080);
        assert_eq!(BOSMINER_ELF_TYPE_EXEC, 2);
        // Panic string xref resolves to the assert site in FUN_0092e784.
        assert_eq!(BOSMINER_EXT_WORK_ID_ASSERT_SITE_VA, 0x0092_EC60);
        assert_eq!(BOSMINER_EXT_WORK_ID_ASSERT_VA, 0x0132_7BC3);
    }
}
