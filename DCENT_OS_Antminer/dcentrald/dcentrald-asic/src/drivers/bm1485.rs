//! BM1485 ASIC driver (Antminer L3 / L3+ / L3++ — Litecoin **Scrypt**) — SCAFFOLD.
//!
//! Queue rank 44 (:207`,
//! H2 #9 / G-4). The BM1485 silicon profile has shipped since
//! (`dcentrald-silicon-profiles/src/bm1485.rs`) with **no driver behind it**;
//! this module closes that stranding.
//!
//! **Tier: Scaffold. Every hardware-touching path REFUSES to energize.** Only
//! the pure/offline surfaces (identity getters, CRC5 frame builders, the
//! `bt8d` baud arithmetic, the PLL divider search) are functional.
//!
//! # Architecture: this EXTENDS the Scrypt lane, it does not invent one
//!
//! DCENT already carries two Scrypt-lane modules — [`super::bm1489`] (L7/L9
//! string-mined scaffold) and `super::scrypt_l7` (the W3-A-accurate L7 driver,
//! behind the default-OFF `scrypt-l7` feature). BM1485 is the *predecessor* of
//! both: `bm1489.rs`'s register map is explicitly documented as **inherited
//! from BM1485** (`bm1489.rs:120-153`). This module is where those inherited
//! addresses actually come from, so it carries the primary citation and the
//! two later modules keep pointing at it.
//!
//! Concretely, this driver adds **no new CRC engine**: the BM1485 CRC5 in
//! `mining-bible-v1/3-asic-protocol/bm1485.md:87-115` is bit-for-bit the same
//! LFSR as the already-shipped [`crate::protocol::crc5`] (poly 0x05, init
//! 0x1F, MSB-first) — proven by `crc5_is_the_already_shipped_bm1387_lfsr`
//! below. All documented BM1485 CRC lengths (32 bits / 64 bits) are
//! byte-aligned, so the existing byte-wise implementation covers every frame.
//!
//! # Held-evidence base (challenge to the queue's "blocked on cgminer-ltc")
//!
//! The queue and `H2-ASIC-GENERATIONS.md:379` list this item as "blocked on
//! acquiring `cgminer-ltc`". That is **false as of 2026-08-03** — we hold the
//! compiled `driver-btm-L3.c` in three separate ARM ELF binaries, plus the
//! stock L3+ firmware image and an L3++ NAND recovery image:
//!
//! | Artifact | Path (under `knowledge-base/`) | md5 |
//! |---|---|---|
//! | stock L3+ `cgminer` | `extractions/antminer-stock/l3plus/sd-tools-l3plus-d3a3/cpio_extracted/usr/bin/cgminer` | `364f38dbe9bb73f259ec37698237d47f` |
//! | VNish 3.8.8 L3+ `cgminer` | `extractions/vnish-farm/l3plus/vnish-3.8.8-original/cpio_extracted/usr/bin/cgminer` | `f1d1700b5d46abd7f69fb63abafdb8b0` |
//! | VNish 3.9.0 L3+ `cgminer` | `extractions/vnish-farm/l3plus/vnish-3.9.0-main/fw_inner/cpio_extracted/usr/bin/cgminer` | `bd79309da91f5dc375cefbdc08d0b1c3` |
//! | stock L3+ firmware | `firmware-archive/Antminer-L3plus-awesome-3.9.tar.gz` | — |
//! | L3++ SD/NAND recovery | `extractions/antminer-stock/l3plus/sd-recover-nand-201904231425/` | — |
//!
//! The stock binary (330,836 B, ARM EABI5, stripped) embeds the source
//! filename `driver-btm-L3.c` and the `__func__` roster `bitmain_L3_detect`
//! / `bitmain_L3_prepare` / `bitmain_L3_init` / `tty_init` /
//! `software_set_address` / `set_frequency{,_i,_with_addr_i}` /
//! `set_asic_ticket_mask` / `bitmain_scanreg` / `get_asic_response` /
//! `pic_heart_beat_func` / `pic_reset` / `flash_pic_freq`.
//!
//! **What the held binary CORRECTS in `bm1485.md`:**
//!
//! - §12 claims the nonce frame is `[HEADER][nonce×4][chip_addr][CRC5]`. The
//!   binary's own decode format string is
//!   `get nonce %02x%02x%02x%02x wc %02x diff %02x crc5 %02x chainid %02x` —
//!   i.e. **`nonce[4] || wc || diff || crc5`** (7 bytes, no leading header
//!   byte; `chainid` is host-side, it is which `/dev/ttyO` the frame arrived
//!   on). The 7-byte total agrees; the field layout does not. Encoded here as
//!   [`RESPONSE_BYTES`] + [`NonceFieldLayout`], with `decode_nonce` still
//!   fail-closed because chip/core attribution is not settled.
//! - §4's 9-byte Write Register frame IS corroborated:
//!   `Set config reg %02x : %02x%02x%02x%02x%02x%02x%02x%02x%02x`.
//! - §7's 4-byte MISC_CONTROL payload IS corroborated:
//!   `Dump MISC Data:[%X][%X][%X][%X]@Chain[%d] -- Chip[%X]`.
//! - §2's "no readable CHIP_ID" IS corroborated: the roster has `check_chain`
//!   / `bitmain_scanreg` / `software_set_address` and the log line
//!   `%s: chain %d has %d ASIC, and addrInterval is %d` — chain-length based
//!   detection, never a register-0x00 identity read. See [`CHIP_ID`].
//!
//! # ⚠ THE BAUD ADJUDICATION (queue-flagged landmine) — see [`operational_baud_plan`]
//!
//! The queue flags "MEDIUM risk **if the 115,384-vs-1,562,500 baud conflict is
//! resolved by guessing**". Adjudicated below from sources, NOT guessed.
//!
//! **They are not the same quantity.** 115,384 is a *boot/enumeration* rate and
//! 1,562,500 is a *post-upgrade operational* rate — the same two-phase split
//! every BM13xx chip has (`dcentrald-api-types/src/baud_switch.rs:6-12`). Both
//! numbers come from ONE table, `bm1485.md:176-183`:
//!
//! ```text
//! BaudRate = 25 MHz / ((bt8d + 1) * 8)
//!   bt8d = 26 → 115384  (boot)
//!   bt8d = 7  → 390625
//!   bt8d = 1  → 1,562,500
//! ```
//!
//! So the "conflict" the queue names is a **category error in the ledger**, not
//! a contradiction in the evidence. Root 's "BM1485 at 1.5625 Mbaud"
//! and `baud_switch.rs:112`'s `target_baud(Bm1485) = 1_562_500` are both
//! describing the *operational* rate; `bm1485.md:165`'s `bt8d = 26` is the
//! *boot* rate. Nothing needs to "win".
//!
//! **But two REAL defects fall out of the same table, and they are NOT
//! resolved here:**
//!
//! 1. **`115,384` is arithmetically impossible.** The doc's own formula at
//!    §8 gives `25e6 / (27 * 8) = 115,740.74` for `bt8d = 26`, and no integer
//!    `bt8d` yields 115,384 (`25e6/(8·x) = 115384 ⇒ x = 27.083`). Our own
//!    `baud_switch.rs:7-8` already documents the correct 115,740. So
//!    `bm1485.md:165`'s "115384" is a transcription slip for the boot rate.
//!    Pinned by `doc_claimed_115384_is_not_producible_by_the_doc_formula`.
//! 2. **The OPERATIONAL rate is genuinely UNRESOLVED**, and the queue did not
//!    name this one. `bm1485.md:183` says "L3+ runs at 1.5625 Mbps after
//!    upgrade" (`bt8d = 1`), but the SAME document's init sequence at
//!    §10 step 6 writes `bt8d = 7` and switches the host to **390,625**. Two
//!    different operational rates, one document, no reconciliation.
//!
//! Held-byte evidence does **not** break the tie, and leans against 1,562,500:
//!
//! - The stock L3+ binary contains **no** 32-bit literal and **no** ASCII
//!   occurrence of `1562500`, `390625`, `115384`, or `115740`. The only
//!   baud-shaped literal present is `115200`. (The `1500000`/`3000000` ASCII
//!   hits are inside scrypt test-vector hex blobs, not baud strings.)
//! - The whole `--bitmain-*` option set is `core-temp`, `fan-ctrl`, `fan-pwm`,
//!   `freq`, `voltage`. There is **no baud option**, and
//!   `etc/cgminer.conf.factory` sets only `"bitmain-freq":"384"`.
//! - `tty_init` drives `/dev/ttyO%d` (AM335x kernel UART) through a termios
//!   mapper whose failure arm is `Unrecognized baud rate: %d,set default baud`.
//!   Neither 1,562,500 nor 390,625 is a standard termios `Bxxxx` rate, and an
//!   AM335x 48 MHz UART cannot divide to either exactly (`48e6/16 = 3e6`;
//!   `3e6/1562500 = 1.92`, `3e6/390625 = 7.68`).
//!
//! **Therefore: FAIL-CLOSED.** [`OPERATIONAL_BAUD`] is `None`,
//! [`operational_baud_plan`] returns `Err`, and [`ChipDriver::max_baud`]
//! returns the *enumeration* rate — this driver refuses to raise baud at all.
//! Both candidates are retained side by side in
//! [`UNRESOLVED_OPERATIONAL_BAUD_CANDIDATES`] so a bench session can measure
//! rather than re-litigate. This honours the standing repo rule: **never raise
//! a driver baud without bench proof** (`MEMORY.md`, BM1366/BM1370 edit-bait).
//!
//! # Known DEFECT in a neighbouring crate (reported, NOT edited here)
//!
//! `dcentrald-api-types/src/baud_switch.rs:131-144` returns `0x1C` from
//! `baud_register(Bm1485)`, grouping BM1485 with BM1387. Per `bm1485.md:128`
//! the BM1485 baud divisor (`bt8d`) lives in **MISC_CONTROL @ `0x18`**;
//! `0x1C` on BM1485 is **`GENERAL_IIC`** (the TMP451 I²C master, `bm1485.md:129`).
//! Writing a baud word to `0x1C` would drive the temperature-sensor I²C master.
//! That file is outside this wave's file grant, so it is reported rather than
//! edited; [`regs::MISC_CONTROL`] / [`regs::GENERAL_IIC`] here are the
//! corrected reference and `baud_register_0x1c_is_the_general_iic_register`
//! pins why.
//!
//! # References
//!
//! - Register map / framing / CRC5 / MISC_CONTROL / init:
//! - Silicon profile (5 rows, 384 MHz nameplate): `dcentrald-silicon-profiles/src/bm1485.rs`
//! - Scrypt family context:
//! - Successor inheritance: `dcentrald-asic/src/drivers/bm1489.rs:120-153`
//! - Baud two-phase model: `dcentrald-api-types/src/baud_switch.rs`

use crate::drivers::{ChipDriver, MiningWork, NonceResult, PllConfig};
use crate::pic::PicController;
use crate::Result;
use dcentrald_hal::fpga_chain::{self, FpgaChain};

// ---------------------------------------------------------------------------
// Identity — NOTE: this chip has no silicon-readable ID
// ---------------------------------------------------------------------------

/// **SYNTHETIC** registry key for BM1485. This value is *not* read from
/// silicon.
///
/// `bm1485.md:24`: "The BM1485 has **no readable CHIP_ID** that's been
/// verified. Driver code (`bitmaintech/cgminer-ltc`) doesn't read register
/// 0x00 to detect chip type — it relies on chain length / config."
///
/// Corroborated by the held stock binary, whose detection roster is
/// `check_chain` / `bitmain_scanreg` / `software_set_address` plus the log
/// line `%s: chain %d has %d ASIC, and addrInterval is %d` — chain-length
/// based, never an identity read.
///
/// `0x1485` follows the Bitmain family naming convention (BM1387→0x1387, …)
/// purely so this driver has a stable `HashMap` key in [`super::ChipRegistry`].
/// **It must never be treated as evidence that a chain reported `0x1485`.**
/// See [`CHIP_ID_IS_SILICON_READABLE`].
pub const CHIP_ID: u16 = 0x1485;

/// `false` — [`CHIP_ID`] is a registry key, not an enumeration response.
///
/// Detect-by-chip-id is structurally unavailable for BM1485. A real bring-up
/// must identify an L3-class chain by **chain length + board/EEPROM identity**,
/// not by a broadcast register-0x00 read. Until such a path exists, this
/// driver stays Scaffold and every hardware entry point refuses.
pub const CHIP_ID_IS_SILICON_READABLE: bool = false;

// ---------------------------------------------------------------------------
// Geometry — the well-sourced constants
// ---------------------------------------------------------------------------

/// Scrypt cores per BM1485 chip = 12.
///
/// The single best-attested BM1485 number: `BM1485_CORE_NUM = 12` from the
/// cgminer-ltc source per `dcentrald-silicon-profiles/src/bm1485.rs:86-87`
/// (`BM1485_CORES_PER_CHIP`), `bm1485.md:3` and `:17`, and re-cited by
/// `bm1489.rs:19` when it inherited the value as a placeholder.
const NUM_CORES_ON_CHIP: u32 = 12;

/// L3+ / L3++ chips per chain-board = 72.
///
/// Mirrors `dcentrald-silicon-profiles/src/bm1485.rs:96`
/// (`BM1485_CHIPS_PER_CHAIN_L3PLUS`), sourced from
/// `SCRYPT_ASIC_CHIPS.md` §77-81 and `bm1485.md:5`.
pub const DEFAULT_CHIPS_PER_CHAIN_L3PLUS: u8 = 72;

/// L3+ / L3++ chain-boards per miner = 4 (NOT the 3 of S9/S17/S19).
///
/// Mirrors `dcentrald-silicon-profiles/src/bm1485.rs:99`
/// (`BM1485_CHAIN_COUNT_L3PLUS`). 72 × 4 = 288 chips total.
pub const DEFAULT_CHAIN_COUNT_L3PLUS: u8 = 4;

/// L3+ nameplate hash frequency = 384 MHz.
///
/// The only `OperatorConfirmed` row in the silicon table
/// (`dcentrald-silicon-profiles/src/bm1485.rs:46-53`, Step 0). Independently
/// corroborated by the held stock firmware's
/// `etc/cgminer.conf.factory:25` — `"bitmain-freq" : "384"` — and by the VNish
/// 3.8.8 L3+ factory config carrying the identical default.
pub const L3PLUS_NAMEPLATE_FREQ_MHZ: u16 = 384;

// ---------------------------------------------------------------------------
// Baud — the queue-flagged landmine, encoded fail-closed
// ---------------------------------------------------------------------------

/// Nominal host-side enumeration baud (8N1).
///
/// `bm1485.md:4` ("Default Baud: 115200 bps"). This is the *nominal* figure a
/// host termios call requests; the chip-side divider actually produces
/// [`BT8D_BOOT_TRUE_BAUD`], which is within standard UART tolerance of it.
pub const ENUM_BAUD_NOMINAL: u32 = 115_200;

/// Chip UART reference clock feeding the `bt8d` divider (25 MHz).
///
/// `bm1485.md:177`. Same 25 MHz reference the BM1387 MiscCtrl `baud_div`
/// formula uses (`wave6-mining/B1-s9-t9-l3-l7-r4/pll.md:62`).
pub const CHIP_UART_REF_HZ: u32 = 25_000_000;

/// `bt8d` divider value at boot/enumeration = 26 (`0x1A`).
///
/// `bm1485.md:165` — `set_misc_ctrl()` default in cgminer-ltc.
pub const BT8D_BOOT: u8 = 26;

/// Chip-side baud produced by a given `bt8d` divider.
///
/// `BaudRate = 25 MHz / ((bt8d + 1) * 8)` — `bm1485.md:177`.
///
/// This is the arithmetic that adjudicates the ledger's "115,384" figure: it
/// is the *only* baud formula the BM1485 evidence base provides, and it cannot
/// produce 115,384 for any integer `bt8d`.
pub const fn bt8d_to_baud(bt8d: u8) -> u32 {
    CHIP_UART_REF_HZ / ((bt8d as u32 + 1) * 8)
}

/// True chip-side boot baud = 115,740 bps (`bt8d = 26`).
///
/// Matches `dcentrald-api-types/src/baud_switch.rs:7-8`, which already
/// documents "true rate 115740 bps from `25 MHz / (26+1) / 8`" for the whole
/// BM13xx/BM14xx family. +0.47 % from the nominal 115,200 — well inside UART
/// tolerance.
pub const BT8D_BOOT_TRUE_BAUD: u32 = bt8d_to_baud(BT8D_BOOT);

/// The figure `bm1485.md:165` prints for `bt8d = 26`. **Retained only to be
/// refuted**, never to be used.
///
/// Not producible by the document's own §8 formula for any integer `bt8d`
/// (`25e6/(8·x) = 115384 ⇒ x = 27.083`). Treat as a transcription slip for the
/// boot rate; the correct value is [`BT8D_BOOT_TRUE_BAUD`].
pub const DOC_CLAIMED_BOOT_BAUD_115384: u32 = 115_384;

/// The two mutually exclusive **operational** baud candidates our evidence
/// base carries, as `(bt8d, baud)`. Deliberately kept side by side.
///
/// - `(7, 390_625)` — `bm1485.md:180` and the §10 step-6 init sequence, which
///   writes `bt8d = 7` and switches the host UART to 390,625.
/// - `(1, 1_562_500)` — `bm1485.md:181` and `:183` ("L3+ runs at 1.5625 Mbps
///   after upgrade"), carried into `baud_switch.rs:112` and root .
///
/// Held L3+ binaries contain **neither** value as a literal, so they do not
/// break the tie. Resolving this requires a bench UART capture on live L3/L3+
/// hardware, or a `tty_init` disassembly of the stock `cgminer`.
pub const UNRESOLVED_OPERATIONAL_BAUD_CANDIDATES: [(u8, u32); 2] = [(7, 390_625), (1, 1_562_500)];

/// **UNRESOLVED** — `None` by construction.
///
/// See [`UNRESOLVED_OPERATIONAL_BAUD_CANDIDATES`] and the module header. Do
/// not replace this with a value without a bench capture landing in the same
/// commit; `operational_baud_is_unresolved_and_fails_closed` pins it.
pub const OPERATIONAL_BAUD: Option<u32> = None;

/// Fail-closed accessor for the post-enumeration mining baud.
///
/// Always `Err` today. A bring-up that needs the upgraded rate must go through
/// here so it cannot silently pick a candidate.
pub fn operational_baud_plan() -> Result<u32> {
    match OPERATIONAL_BAUD {
        Some(baud) => Ok(baud),
        None => Err(crate::AsicError::InvalidParameter(format!(
            "BM1485 operational baud is UNRESOLVED — bm1485.md gives TWO \
             irreconcilable post-upgrade rates (bt8d=7 -> {} and bt8d=1 -> {}), \
             and no held L3/L3+ binary contains either as a literal. The chain \
             stays at the {} enumeration rate until a bench UART capture \
             settles it. [rank-44 fail-closed]",
            UNRESOLVED_OPERATIONAL_BAUD_CANDIDATES[0].1,
            UNRESOLVED_OPERATIONAL_BAUD_CANDIDATES[1].1,
            ENUM_BAUD_NOMINAL,
        ))),
    }
}

// ---------------------------------------------------------------------------
// Wire framing — BM1387-era, NO 0x55 0xAA preamble
// ---------------------------------------------------------------------------

/// BM1485 nonce response size on the wire = 7 bytes.
///
/// Both sources agree on the length. `bm1485.md:236-240` says 7 bytes; the
/// held stock binary's decode format string accounts for exactly 7
/// (`nonce %02x%02x%02x%02x wc %02x diff %02x crc5 %02x`). They disagree on
/// the *layout* — see [`NonceFieldLayout`].
///
/// `bm1485.md:242`: the response has **no `0xAA 0x55` preamble**; bare bytes
/// are returned. (`bm1489.rs:88-101` inherited this 7-byte framing.)
pub const RESPONSE_BYTES: usize = 7;

/// The two competing BM1485 nonce-frame field layouts, both 7 bytes.
///
/// `decode_nonce` refuses rather than choosing. Resolving this needs the same
/// bench capture as the baud question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceFieldLayout {
    /// `bm1485.md:236-240`: `[HEADER][nonce×4][chip_addr][CRC5]`.
    DocHeaderNonceAddrCrc,
    /// Held stock `cgminer` format string
    /// `get nonce %02x%02x%02x%02x wc %02x diff %02x crc5 %02x chainid %02x`:
    /// `[nonce×4][wc][diff][CRC5]`, with `chainid` supplied host-side by which
    /// `/dev/ttyO` the frame arrived on. **Preferred** — it is emitted by the
    /// shipped decoder itself rather than transcribed.
    BinaryNonceWcDiffCrc,
}

/// BM1485 command headers. `bm1485.md:30-40`.
///
/// Bit layout: `TYPE = bits[6:5]` (`0b01` = command, `0b10`… see `SEND_WORK`),
/// `ALL = bit 4`, `CMD = bits[3:0]` (0=SetAddr, 1=Write, 2=Read, 3=Inactive).
pub mod headers {
    /// Set chip address, single. `bm1485.md:32`.
    pub const SET_ADDRESS: u8 = 0x40;
    /// Write register, single. `bm1485.md:33`.
    pub const WRITE_REG: u8 = 0x41;
    /// Read register, single. `bm1485.md:34`.
    pub const READ_REG: u8 = 0x42;
    /// Write register, broadcast (`WRITE_REG | ALL`). `bm1485.md:35`.
    pub const WRITE_REG_ALL: u8 = 0x51;
    /// Read register, broadcast (`READ_REG | ALL`). `bm1485.md:36`.
    pub const READ_REG_ALL: u8 = 0x52;
    /// Chain inactive, broadcast. `bm1485.md:37`.
    pub const CHAIN_INACTIVE: u8 = 0x53;
    /// Send work. `bm1485.md:38` — note this is `0x20`, **not** the `0x21`
    /// SHA-256 marker used by BM1387/BM139x.
    pub const SEND_WORK: u8 = 0x20;
}

/// Length byte carried by the 5-byte command frames. `bm1485.md:60`.
///
/// Fixed `0x04` — explicitly NOT the `0x05` that BM1387 and BM1397+ use.
pub const CMD_FRAME_LEN_BYTE: u8 = 0x04;

/// Length byte carried by the 9-byte register-write frame. `bm1485.md:69`.
///
/// Corroborated by the held stock binary's
/// `Set config reg %02x : %02x%02x%02x%02x%02x%02x%02x%02x%02x` (9 payload
/// bytes printed).
pub const WRITE_FRAME_LEN_BYTE: u8 = 0x08;

/// Build a BM1485 5-byte **read register** frame.
///
/// `[hdr][0x04][chip_addr][reg][CRC5]`, CRC5 over the leading 4 bytes
/// (`bm1485.md:54-61`; the doc's `len` is in BITS — 32 bits = these 4 bytes).
/// Pass `broadcast = true` for header `0x52`.
pub fn read_reg_frame(chip_addr: u8, reg: u8, broadcast: bool) -> [u8; 5] {
    let hdr = if broadcast {
        headers::READ_REG_ALL
    } else {
        headers::READ_REG
    };
    let body = [hdr, CMD_FRAME_LEN_BYTE, chip_addr, reg];
    [
        body[0],
        body[1],
        body[2],
        body[3],
        crate::protocol::crc5(&body),
    ]
}

/// Build a BM1485 5-byte **chain-inactive** frame. `bm1485.md:73-76`.
pub fn chain_inactive_frame() -> [u8; 5] {
    let body = [headers::CHAIN_INACTIVE, CMD_FRAME_LEN_BYTE, 0x00, 0x00];
    [
        body[0],
        body[1],
        body[2],
        body[3],
        crate::protocol::crc5(&body),
    ]
}

/// Build a BM1485 5-byte **set chip address** frame. `bm1485.md:78-81`.
pub fn set_address_frame(chip_addr: u8) -> [u8; 5] {
    let body = [headers::SET_ADDRESS, CMD_FRAME_LEN_BYTE, chip_addr, 0x00];
    [
        body[0],
        body[1],
        body[2],
        body[3],
        crate::protocol::crc5(&body),
    ]
}

/// Build a BM1485 9-byte **write register** frame.
///
/// `[hdr][0x08][chip_addr][reg][D0..D3][CRC5]`, CRC5 over the leading 8 bytes
/// (`bm1485.md:63-71`; doc `len` = 64 bits = these 8 bytes).
///
/// ⚠ **Byte order is UNRESOLVED.** `bm1485.md:70` says the payload comes from
/// `memcpy(&cmd_buf[4], &reg_data, 4)`, i.e. it inherits *host* endianness —
/// little-endian on the L3+'s AM335x. That is the opposite of the big-endian
/// convention BM1387/BM139x use (`crate::protocol::fifo_cmd_write_reg_full`).
/// Callers therefore supply the four payload bytes explicitly; this helper
/// deliberately does **not** take a `u32` and pick an order.
pub fn write_reg_frame(chip_addr: u8, reg: u8, payload: [u8; 4], broadcast: bool) -> [u8; 9] {
    let hdr = if broadcast {
        headers::WRITE_REG_ALL
    } else {
        headers::WRITE_REG
    };
    let body = [
        hdr,
        WRITE_FRAME_LEN_BYTE,
        chip_addr,
        reg,
        payload[0],
        payload[1],
        payload[2],
        payload[3],
    ];
    let mut frame = [0u8; 9];
    frame[..8].copy_from_slice(&body);
    frame[8] = crate::protocol::crc5(&body);
    frame
}

// ---------------------------------------------------------------------------
// Register map — bm1485.md §6 (the full 18-entry table)
// ---------------------------------------------------------------------------

/// BM1485 register addresses, complete per `bm1485.md:120-139`.
///
/// This is the **primary** citation for the addresses that `bm1489.rs:154-181`
/// inherits (`CHIP_ADDRESS`/`PLL0_PARAMETER`/`HASH_COUNTING`/`TICKET_MASK`/
/// `MISC_CONTROL`/`CORE_REG_CTRL`). Confidence is HIGH for the map as
/// transcribed from cgminer-ltc; it is **not** live-verified on DCENT
/// hardware, and this driver never writes it.
pub mod regs {
    /// Chip address. `bm1485.md:122`. **The cgminer-ltc driver never reads
    /// this for identity** — see [`super::CHIP_ID_IS_SILICON_READABLE`].
    pub const CHIP_ADDR: u8 = 0x00;
    /// Real-time hashrate counter (read-only). `bm1485.md:123`.
    pub const HASHRATE: u8 = 0x04;
    /// PLL parameter — hash clock. `bm1485.md:124`.
    pub const PLL_PARAMETER: u8 = 0x08;
    /// Start Nonce Offset. `bm1485.md:125`.
    pub const SNO: u8 = 0x0C;
    /// Hash Counting Number. `bm1485.md:126`.
    pub const HCN: u8 = 0x10;
    /// Difficulty filter. `bm1485.md:127`.
    pub const TICKET_MASK: u8 = 0x14;
    /// Misc control — **carries the `bt8d` baud divisor**. `bm1485.md:128`.
    /// See [`super::misc_control_with_bt8d`].
    pub const MISC_CONTROL: u8 = 0x18;
    /// I²C master to the TMP451 temperature sensor. `bm1485.md:129`.
    ///
    /// ⚠ This is the address `baud_switch.rs:134` currently returns from
    /// `baud_register(Bm1485)` — see the module header's defect note.
    pub const GENERAL_IIC: u8 = 0x1C;
    /// EEPROM authentication. `bm1485.md:130`.
    pub const SECURITY_IIC: u8 = 0x20;
    /// Signature challenge. `bm1485.md:131`.
    pub const SIG_INPUT: u8 = 0x24;
    /// Signature response part 0 (read-only). `bm1485.md:132`.
    pub const SIG_NONCE_0: u8 = 0x28;
    /// Signature response part 1 (read-only). `bm1485.md:133`.
    pub const SIG_NONCE_1: u8 = 0x2C;
    /// Signature ID (read-only). `bm1485.md:134`.
    pub const SIG_ID: u8 = 0x30;
    /// Security state. `bm1485.md:135`.
    pub const SEC_CTRL_STATUS: u8 = 0x34;
    /// SRAM status (read-only). `bm1485.md:136`.
    pub const MEMORY_STATUS: u8 = 0x38;
    /// Indirect core access, write. `bm1485.md:137`.
    pub const CORE_CMD_IN: u8 = 0x3C;
    /// Indirect core response, read. `bm1485.md:138`.
    pub const CORE_RESP_OUT: u8 = 0x40;
    /// External temperature ADC (read-only). `bm1485.md:139`.
    pub const EXT_TEMP_SENSOR: u8 = 0x44;
}

// ---------------------------------------------------------------------------
// MISC_CONTROL bt8d field — the mechanism the baud question hinges on
// ---------------------------------------------------------------------------

/// Bit position of the `bt8d` field within the 32-bit MISC_CONTROL word.
///
/// `bm1485.md:144-148` places `bt8d` at **byte 2, bits [4:0]**. Byte 2 of a
/// 32-bit word is bits 23:16, so `bt8d` occupies bits **20:16**.
pub const MISC_CONTROL_BT8D_SHIFT: u32 = 16;

/// Width mask for the 5-bit `bt8d` field (max representable divider = 31).
pub const MISC_CONTROL_BT8D_MASK: u32 = 0x1F;

/// Replace the `bt8d` field of a MISC_CONTROL word.
///
/// ⚠ **DOC-DERIVED, NOT LIVE-VERIFIED, and intentionally without a caller.**
/// It exists so a future bench session can *compute* the candidate words for
/// the two unresolved dividers instead of hand-packing them, and so the field
/// placement is pinned by a test rather than living only in prose. Nothing in
/// this driver writes MISC_CONTROL — `set_frequency`/`init_chain` refuse
/// first.
///
/// `bt8d` is clamped to the 5-bit field width.
pub const fn misc_control_with_bt8d(base: u32, bt8d: u8) -> u32 {
    let field = (bt8d as u32) & MISC_CONTROL_BT8D_MASK;
    (base & !(MISC_CONTROL_BT8D_MASK << MISC_CONTROL_BT8D_SHIFT))
        | (field << MISC_CONTROL_BT8D_SHIFT)
}

// ---------------------------------------------------------------------------
// Chain address assignment — also unresolved
// ---------------------------------------------------------------------------

/// Address stride `bm1485.md:206-208` claims for L3+ chain enumeration.
///
/// The doc's init sequence comments `# NOTE: BM1485 uses i, not i*4
/// (vs BM1387)` — i.e. stride 1.
pub const DOC_ADDR_STRIDE_L3PLUS: u8 = 1;

/// Fail-closed accessor for the chain address stride.
///
/// Always `Err` today. Two in-tree sources disagree for a 72-chip L3+ chain:
///
/// - `bm1485.md:206-208` → stride **1**.
/// - The Bitmain chip-count **bucket** rule
///   (byte-identical in
///   four AMTC jig binaries: `>128→1`, `64<N≤128→2`, `32<N≤64→4`, `≤32→refuse`)
///   → 72 chips falls in `64 < N ≤ 128`, giving stride **2**.
///
/// The held stock L3+ binary proves the concept is live
/// (`addrInterval = '%d'`, `%s: chain %d has %d ASIC, and addrInterval is %d`)
/// but the emitted value is only visible at runtime, so it does not arbitrate.
/// Guessing wrong collapses chain addressing, so this refuses.
pub fn addr_stride_plan(_chips_per_chain: u8) -> Result<u8> {
    Err(crate::AsicError::InvalidParameter(
        "BM1485 chain address stride is UNRESOLVED — bm1485.md:206 says stride 1 \
         while the four-jig addrInterval bucket rule gives stride 2 for a \
         72-chip L3+ chain. The held stock cgminer logs addrInterval at runtime \
         only. Refusing rather than collapsing chain addressing. [rank-44 fail-closed]"
            .into(),
    ))
}

// ---------------------------------------------------------------------------
// PLL — formula documented, register encoding is NOT
// ---------------------------------------------------------------------------

/// PLL reference crystal (MHz). `bm1485.md:189` — same formula as BM1387.
const CLKI_MHZ: f64 = 25.0;

/// Feedback-divider search bounds covering the documented L3+ band.
///
/// `bm1485.md:192` lists common L3+ frequencies 384–500 MHz; the shipped
/// silicon table spans 270–480 MHz
/// (`dcentrald-silicon-profiles/src/bm1485.rs:29-70`). These bounds cover both
/// without asserting either is the hardware limit.
const FB_DIV_MIN: u16 = 24;
const FB_DIV_MAX: u16 = 320;

/// Sentinel written into [`PllConfig::reg_value`] by [`ChipDriver::pll_params`].
///
/// `bm1485.md:189-192` gives the PLL **formula** (`freq = 25 · FBDIV /
/// (REFDIV · POSTDIV1 · POSTDIV2)`) but only says the driver "writes 4 bytes
/// encoding (FBDIV, REFDIV, POSTDIV1, POSTDIV2)" — the **bit layout is never
/// specified**, and the BM1387 layout must not be assumed (BM1387's PLL lives
/// at `0x0C`, BM1485's at `0x08`, so they are not the same register).
///
/// `0` is chosen deliberately: with no PLLEN bit set it is inert, so even an
/// erroneous write could not command a clock. Pinned by
/// `pll_params_refuses_to_encode_a_register_value`.
pub const PLL_REG_VALUE_UNRESOLVED: u32 = 0;

/// Solve the documented PLL formula for the closest achievable frequency.
///
/// Returns `(actual_mhz, fbdiv, refdiv, postdiv1, postdiv2)`. This is pure
/// divider arithmetic from `bm1485.md:189` — it makes **no claim about
/// register encoding**; see [`PLL_REG_VALUE_UNRESOLVED`].
fn bm1485_pll_dividers(target_mhz: u16) -> (u16, u16, u8, u8, u8) {
    let target = target_mhz.clamp(100, 700) as f64;

    let mut best_freq = 0.0f64;
    let mut best_fb: u16 = FB_DIV_MIN;
    let mut best_ref: u8 = 1;
    let mut best_pd1: u8 = 1;
    let mut best_pd2: u8 = 1;
    let mut best_diff = f64::MAX;

    for refdiv in [1u8, 2] {
        for postdiv1 in 1..=7u8 {
            for postdiv2 in 1..=7u8 {
                if postdiv1 < postdiv2 {
                    continue;
                }
                let divider = (refdiv as f64) * (postdiv1 as f64) * (postdiv2 as f64);
                let fbdiv_f = target * divider / CLKI_MHZ;
                let fbdiv = fbdiv_f.round() as u16;
                if !(FB_DIV_MIN..=FB_DIV_MAX).contains(&fbdiv) {
                    continue;
                }
                let actual = CLKI_MHZ * (fbdiv as f64) / divider;
                let diff = (actual - target).abs();
                if diff < best_diff {
                    best_diff = diff;
                    best_freq = actual;
                    best_fb = fbdiv;
                    best_ref = refdiv;
                    best_pd1 = postdiv1;
                    best_pd2 = postdiv2;
                }
            }
        }
    }

    (
        best_freq.round() as u16,
        best_fb,
        best_ref,
        best_pd1,
        best_pd2,
    )
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// BM1485 driver — SCAFFOLD, refuses to energize.
///
/// Registered Scaffold-tier in [`super::ChipRegistry`], so it is absent from
/// `production()` and needs BOTH `DCENT_ALLOW_SCAFFOLD_ASIC_DRIVERS=1` and
/// `DCENT_CONFIRM_SCAFFOLD_DRIVERS_ARE_SIMULATOR_STUBS=1` to resolve at all.
/// Even then every hardware method returns `Err`.
///
/// Blockers that must close before this can advance past Scaffold:
///   1. Operational baud (`bt8d = 7` vs `bt8d = 1`) — bench UART capture.
///   2. Chain address stride (1 vs 2) — read `addrInterval` off a live L3+.
///   3. PLL register bit layout — disassemble `set_frequency` in the held
///      stock `cgminer` (`driver-btm-L3.c`).
///   4. Nonce field layout ([`NonceFieldLayout`]) — passive UART RX capture.
///   5. Scrypt work-frame byte layout — `bm1485.md:225-232` is internally
///      inconsistent (its own byte ranges run to `[90..91]` for a frame it
///      calls 86 bytes).
///   6. A non-chip-id detection path ([`CHIP_ID_IS_SILICON_READABLE`]).
///   7. PIC16F1704 voltage envelope for the L3+ hashboard.
pub struct Bm1485Driver;

impl Bm1485Driver {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Bm1485Driver {
    fn default() -> Self {
        Self::new()
    }
}

impl ChipDriver for Bm1485Driver {
    fn chip_id(&self) -> u16 {
        // SYNTHETIC registry key — see CHIP_ID / CHIP_ID_IS_SILICON_READABLE.
        CHIP_ID
    }

    fn chip_name(&self) -> &'static str {
        "BM1485"
    }

    fn cores_per_chip(&self) -> u32 {
        NUM_CORES_ON_CHIP
    }

    fn response_length(&self) -> usize {
        RESPONSE_BYTES
    }

    fn default_baud(&self) -> u32 {
        ENUM_BAUD_NOMINAL
    }

    fn max_baud(&self) -> u32 {
        // FAIL-CLOSED: equal to default_baud() — this driver refuses to raise
        // baud at all while the operational rate is unresolved. See
        // `operational_baud_plan`. Standing repo rule: never raise a driver
        // baud without bench proof.
        ENUM_BAUD_NOMINAL
    }

    fn init_chain(&self, _chain: &mut FpgaChain, chip_count: u8, freq_mhz: u16) -> Result<()> {
        tracing::warn!(
            chip_count = chip_count,
            freq_mhz = freq_mhz,
            "BM1485 init_chain: SCAFFOLD — refuses to energize. Operational baud, \
             chain address stride, and PLL register encoding are all unresolved; \
             L3+ also has no FPGA (AM335x kernel /dev/ttyO UARTs), so the \
             FpgaChain transport does not model it."
        );
        Err(crate::AsicError::InvalidParameter(
            "BM1485 (L3/L3+/L3++) driver is a fail-closed scaffold. Blocked on: \
             operational baud (bt8d=7 vs bt8d=1), chain address stride (1 vs 2), \
             PLL register bit layout, and the AM335x kernel-UART transport port. \
             [rank-44 SCAFFOLD]"
                .into(),
        ))
    }

    fn set_frequency(&self, _chain: &mut FpgaChain, chip_addr: u8, freq_mhz: u16) -> Result<()> {
        tracing::warn!(
            chip_addr = format_args!("0x{:02X}", chip_addr),
            freq_mhz = freq_mhz,
            "BM1485 set_frequency: SCAFFOLD — PLL_PARAMETER (0x08) bit layout is \
             not specified by any held source; refusing to write a guessed word"
        );
        Err(crate::AsicError::InvalidParameter(
            "BM1485 set_frequency refused: bm1485.md gives the PLL formula but not \
             the PLL_PARAMETER register bit layout. [rank-44 SCAFFOLD]"
                .into(),
        ))
    }

    fn set_voltage(&self, _pic: &mut PicController, voltage_mv: u16) -> Result<()> {
        // Deliberately NOT the `Ok(())` no-op that bm1489.rs/scrypt_l7.rs use.
        // Those chips are NoPic / ISL68127 so their PIC path is genuinely
        // inert. BM1485 is the opposite: `bm1485.md:246` puts a real
        // **PIC16F1704 at I²C 0x55** on every L3+ hashboard, same family as
        // S9. A silent success here would let a caller believe a DAC write
        // landed. The DAC transfer function for the L3+ board is not
        // established (the silicon table's 9.6-10.4 V rows are the *chain*
        // rail, while bm1485.md:246 describes a 0.6-0.8 V core rail), so this
        // refuses.
        tracing::warn!(
            voltage_mv = voltage_mv,
            "BM1485 set_voltage: SCAFFOLD — L3+ has a real PIC16F1704 @ 0x55 but \
             no established DAC transfer function; refusing rather than \
             silently succeeding"
        );
        Err(crate::AsicError::InvalidParameter(
            "BM1485 set_voltage refused: L3+ PIC16F1704 DAC transfer function is \
             not established (chain-rail vs core-rail sources disagree). \
             [rank-44 SCAFFOLD]"
                .into(),
        ))
    }

    fn send_work(&self, _chain: &mut FpgaChain, _work: &MiningWork) -> Result<u16> {
        tracing::warn!(
            "BM1485 send_work: SCAFFOLD — Scrypt work-frame layout unresolved \
             (bm1485.md:225-232 is self-inconsistent)"
        );
        Err(crate::AsicError::InvalidParameter(
            "BM1485 send_work refused: the Scrypt work frame in bm1485.md:225-232 \
             is internally inconsistent (byte ranges reach [90..91] for a frame it \
             calls 86 bytes), and MiningWork carries SHA-256-shaped midstates that \
             Scrypt does not use. [rank-44 SCAFFOLD]"
                .into(),
        ))
    }

    fn decode_nonce(&self, raw: &[u32; 2]) -> Result<NonceResult> {
        // Deliberately NOT the synthetic decode bm1489.rs/scrypt_l7.rs return.
        // Two 7-byte layouts are in play (see NonceFieldLayout) and a wrong
        // choice mis-attributes every nonce to the wrong chip, which would
        // silently corrupt chip-health and autotuner data.
        tracing::warn!(
            raw0 = format_args!("0x{:08X}", raw[0]),
            raw1 = format_args!("0x{:08X}", raw[1]),
            "BM1485 decode_nonce: SCAFFOLD — two competing 7-byte field layouts"
        );
        Err(crate::AsicError::InvalidParameter(
            "BM1485 decode_nonce refused: bm1485.md:236-240 says \
             [HEADER][nonce x4][chip_addr][CRC5] while the held stock cgminer \
             decoder prints [nonce x4][wc][diff][CRC5]. Both are 7 bytes; picking \
             wrong mis-attributes every nonce. [rank-44 SCAFFOLD]"
                .into(),
        ))
    }

    fn baud_reg_value(&self, target_baud: u32, fpga_clock_hz: u32) -> u32 {
        // Standard FPGA divisor formula, kept for trait conformance only.
        // INERT for L3/L3+: that platform is an AM335x BeagleBone driving
        // kernel `/dev/ttyO{0..}` UARTs through termios (held binary:
        // `tty_init` + "/dev/ttyO%d"), with no FPGA in the chain path at all.
        let div = fpga_clock_hz / (16 * target_baud.max(1));
        div.saturating_sub(1)
    }

    fn ctrl_reg_value(&self) -> u32 {
        // BM1485 uses BM1387-era framing with NO 0x55 0xAA preamble
        // (bm1485.md:28), so the FPGA BM139X mode bit must stay CLEAR — this
        // is the one place BM1485 must NOT copy bm1489.rs/scrypt_l7.rs, which
        // both set CTRL_BM139X. Scrypt has no midstates, so MIDSTATE_CNT = 0.
        // Inert on L3+ (no FPGA); meaningful only if an L3-class hashboard is
        // ever driven from a Zynq carrier.
        fpga_chain::CTRL_ENABLE
    }

    fn job_interval_ms(&self, _chip_count: u8, _freq_mhz: u16) -> u32 {
        // Conservative placeholder. BM1485 nonce throughput is tiny (12 cores
        // at ~1.75 MH/s per chip per
        // `dcentrald-silicon-profiles/src/bm1485.rs:102`), so this is not a
        // safety-relevant value and no work is dispatched anyway
        // (`send_work` refuses).
        10
    }

    fn ticket_mask(&self, difficulty: u32) -> u32 {
        // Pure SSOT encode for trait conformance. `bm1489.rs:569` records that
        // the "predecessor BM1485 was bit-reversed", but no held BM1485 source
        // states the TICKET_MASK (0x14) encoding, and nothing consumes this
        // (init_chain/send_work refuse). Kept on the plain encoding rather than
        // asserting the unverified bit-reversal.
        dcentrald_common::ticket_mask_from_difficulty(
            dcentrald_common::TicketMaskEncoding::PlainDiffMinusOne,
            difficulty,
        )
    }

    fn pll_params(&self, freq_mhz: u16) -> PllConfig {
        let (actual_freq, fb_div, ref_div, post_div1, post_div2) = bm1485_pll_dividers(freq_mhz);

        if actual_freq != freq_mhz {
            tracing::debug!(
                target = freq_mhz,
                actual = actual_freq,
                "BM1485 PLL: closest achievable divider solution is {} MHz \
                 (formula bm1485.md:189; register encoding UNRESOLVED)",
                actual_freq,
            );
        }

        PllConfig {
            fb_div,
            ref_div,
            post_div1,
            post_div2,
            // UNRESOLVED — inert sentinel, never a guessed encoding.
            reg_value: PLL_REG_VALUE_UNRESOLVED,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_a_synthetic_key_not_a_silicon_read() {
        let d = Bm1485Driver::new();
        assert_eq!(d.chip_id(), 0x1485);
        assert_eq!(d.chip_id(), CHIP_ID);
        assert_eq!(d.chip_name(), "BM1485");
        // The load-bearing half: BM1485 has no readable CHIP_ID
        // (bm1485.md:24). Flipping this to `true` without shipping a real
        // register-0x00 identity read would be a fabrication.
        assert!(
            !CHIP_ID_IS_SILICON_READABLE,
            "BM1485 has no verified readable CHIP_ID (bm1485.md:24); \
             detection cannot be by chip id"
        );
    }

    #[test]
    fn geometry_matches_the_silicon_profile() {
        let d = Bm1485Driver::new();
        // dcentrald-silicon-profiles/src/bm1485.rs:87/96/99.
        assert_eq!(d.cores_per_chip(), 12);
        assert_eq!(
            NUM_CORES_ON_CHIP,
            dcentrald_silicon_profiles::bm1485::BM1485_CORES_PER_CHIP,
            "driver and silicon layers must agree on BM1485 core count"
        );
        assert_eq!(
            DEFAULT_CHIPS_PER_CHAIN_L3PLUS,
            dcentrald_silicon_profiles::bm1485::BM1485_CHIPS_PER_CHAIN_L3PLUS as u8
        );
        assert_eq!(
            DEFAULT_CHAIN_COUNT_L3PLUS,
            dcentrald_silicon_profiles::bm1485::BM1485_CHAIN_COUNT_L3PLUS as u8
        );
        assert_eq!(
            DEFAULT_CHIPS_PER_CHAIN_L3PLUS as u32 * DEFAULT_CHAIN_COUNT_L3PLUS as u32,
            288,
            "L3+ total chip count"
        );
    }

    #[test]
    fn nameplate_freq_matches_the_operator_confirmed_profile_row() {
        // Silicon table Step 0 is the only OperatorConfirmed row, and the held
        // stock firmware's cgminer.conf.factory carries "bitmain-freq":"384".
        let step0 = dcentrald_silicon_profiles::bm1485::BM1485_TABLE
            .by_step(0)
            .expect("BM1485 silicon table has a Step 0");
        assert_eq!(step0.freq_mhz, L3PLUS_NAMEPLATE_FREQ_MHZ as u32);
        assert_eq!(L3PLUS_NAMEPLATE_FREQ_MHZ, 384);
    }

    // ---- THE BAUD ADJUDICATION ----

    #[test]
    fn bt8d_formula_reproduces_the_documented_divider_table() {
        // bm1485.md:178-181 — the whole table, from the doc's own §8 formula.
        assert_eq!(bt8d_to_baud(1), 1_562_500);
        assert_eq!(bt8d_to_baud(7), 390_625);
        // ...and bt8d=26, the boot divider.
        assert_eq!(bt8d_to_baud(26), 115_740);
        assert_eq!(BT8D_BOOT, 26);
        assert_eq!(BT8D_BOOT_TRUE_BAUD, 115_740);
    }

    #[test]
    fn doc_claimed_115384_is_not_producible_by_the_doc_formula() {
        // bm1485.md:165 prints "bt8d = 26 (= 0x1A -> 115384 baud)". The same
        // document's §8 formula cannot produce 115384 for ANY integer bt8d.
        // This is the arithmetic that dissolves the ledger's "115,384 vs
        // 1,562,500 conflict": 115384 is a mis-transcribed BOOT rate, and the
        // correct boot rate is 115,740 (already documented in
        // dcentrald-api-types/src/baud_switch.rs:7-8).
        for bt8d in 0u8..=31 {
            assert_ne!(
                bt8d_to_baud(bt8d),
                DOC_CLAIMED_BOOT_BAUD_115384,
                "no integer bt8d produces the doc's claimed 115384"
            );
        }
        // And the true boot rate is within UART tolerance of nominal 115200.
        let ppm_err =
            (BT8D_BOOT_TRUE_BAUD as f64 - ENUM_BAUD_NOMINAL as f64) / ENUM_BAUD_NOMINAL as f64;
        assert!(
            ppm_err.abs() < 0.01,
            "boot divider must land within 1% of nominal 115200, got {ppm_err}"
        );
    }

    #[test]
    fn boot_and_operational_baud_are_different_lifecycle_phases() {
        // The core adjudication: 115,384/115,740 (bt8d=26) is enumeration and
        // 1,562,500 (bt8d=1) is post-upgrade mining. They were never rival
        // answers to one question — same two-phase split as every other
        // BM13xx chip (baud_switch.rs:6-12).
        assert!(
            BT8D_BOOT_TRUE_BAUD < UNRESOLVED_OPERATIONAL_BAUD_CANDIDATES[0].1,
            "boot rate must be below every operational candidate"
        );
        assert!(BT8D_BOOT_TRUE_BAUD < UNRESOLVED_OPERATIONAL_BAUD_CANDIDATES[1].1);
        // Both candidates are real divider values, not invented numbers.
        for (bt8d, baud) in UNRESOLVED_OPERATIONAL_BAUD_CANDIDATES {
            assert_eq!(
                bt8d_to_baud(bt8d),
                baud,
                "candidate ({bt8d}, {baud}) must satisfy the documented formula"
            );
        }
    }

    #[test]
    fn operational_baud_is_unresolved_and_fails_closed() {
        assert!(
            OPERATIONAL_BAUD.is_none(),
            "bm1485.md gives TWO post-upgrade rates (bt8d=7 -> 390625 at :216, \
             bt8d=1 -> 1562500 at :181/:183) and no held L3+ binary contains \
             either literal. Do not pick one without a bench capture."
        );
        let err = operational_baud_plan().expect_err("must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("UNRESOLVED"), "error must say so: {msg}");
        assert!(msg.contains("390625") && msg.contains("1562500"));
    }

    #[test]
    fn driver_refuses_to_raise_baud_above_enumeration() {
        let d = Bm1485Driver::new();
        assert_eq!(d.default_baud(), 115_200);
        // The fail-closed encoding of the unresolved conflict: max == default.
        assert_eq!(
            d.max_baud(),
            d.default_baud(),
            "BM1485 must not advertise a mining baud it cannot prove"
        );
        for (_, candidate) in UNRESOLVED_OPERATIONAL_BAUD_CANDIDATES {
            assert!(
                d.max_baud() < candidate,
                "max_baud must stay below every unproven candidate ({candidate})"
            );
        }
    }

    #[test]
    fn baud_register_0x1c_is_the_general_iic_register() {
        // Documents the defect reported in the module header:
        // `dcentrald-api-types/src/baud_switch.rs:134` returns 0x1C from
        // `baud_register(Bm1485)` by grouping BM1485 with BM1387. On BM1485
        // the bt8d divisor lives in MISC_CONTROL (0x18) and 0x1C is the
        // TMP451 I2C master. If baud_switch.rs is ever corrected, this test
        // stays true — it pins the BM1485 map, not the other crate.
        assert_eq!(regs::MISC_CONTROL, 0x18, "bt8d lives here (bm1485.md:128)");
        assert_eq!(regs::GENERAL_IIC, 0x1C, "TMP451 I2C master (bm1485.md:129)");
        assert_ne!(
            regs::MISC_CONTROL,
            regs::GENERAL_IIC,
            "a baud write aimed at 0x1C would hit the temp-sensor I2C master"
        );
    }

    #[test]
    fn misc_control_bt8d_field_sits_in_byte_2_bits_4_0() {
        // bm1485.md:144-148: bt8d = byte 2, bits [4:0] => word bits 20:16.
        assert_eq!(MISC_CONTROL_BT8D_SHIFT, 16);
        assert_eq!(MISC_CONTROL_BT8D_MASK, 0x1F);
        assert_eq!(misc_control_with_bt8d(0, BT8D_BOOT), 0x001A_0000);
        assert_eq!(misc_control_with_bt8d(0, 1), 0x0001_0000);
        assert_eq!(misc_control_with_bt8d(0, 7), 0x0007_0000);
        // Field replacement must not disturb neighbouring bits.
        let base = 0xFFFF_FFFFu32;
        assert_eq!(misc_control_with_bt8d(base, 1), 0xFFE1_FFFF);
        // Over-wide input is clamped to the 5-bit field, never bleeding into
        // the adjacent inv_clko (bit 21) / rfs (bit 22) fields.
        assert_eq!(misc_control_with_bt8d(0, 0xFF), 0x001F_0000);
    }

    // ---- FRAMING / CRC5 REUSE ----

    #[test]
    fn crc5_is_the_already_shipped_bm1387_lfsr() {
        // bm1485.md:87-115 spells out a bit-level CRC5 whose taps are
        //   out[0]=in[4]^din; out[1]=in[0]; out[2]=in[1]^in[4]^din;
        //   out[3]=in[2]; out[4]=in[3];  init all-ones
        // i.e. left shift with feedback XORed into bits 0 and 2 (poly 0x05),
        // init 0x1F, MSB-first. That is byte-for-byte what
        // crate::protocol::crc5 already implements. Reference port below; if
        // the two ever diverge, this driver's frame builders are wrong.
        fn doc_crc5_bits(data: &[u8], bit_len: usize) -> u8 {
            let mut crcin = [1u8; 5];
            for i in 0..bit_len {
                let din = (data[i / 8] >> (7 - (i % 8))) & 1;
                let mut crcout = [0u8; 5];
                crcout[0] = crcin[4] ^ din;
                crcout[1] = crcin[0];
                crcout[2] = crcin[1] ^ crcin[4] ^ din;
                crcout[3] = crcin[2];
                crcout[4] = crcin[3];
                crcin = crcout;
            }
            (crcin[4] << 4) | (crcin[3] << 3) | (crcin[2] << 2) | (crcin[1] << 1) | crcin[0]
        }

        // Every documented BM1485 CRC length is byte-aligned (32 bits and 64
        // bits, bm1485.md:61/:71), so the shipped byte-wise engine covers all
        // real frames — no new CRC code is needed for this chip.
        let vectors: [&[u8]; 5] = [
            &[0x52, 0x04, 0x00, 0x00],
            &[0x53, 0x04, 0x00, 0x00],
            &[0x40, 0x04, 0x47, 0x00],
            &[0x51, 0x08, 0x00, 0x18, 0x00, 0x1A, 0x00, 0x00],
            &[0x41, 0x08, 0x04, 0x14, 0xDE, 0xAD, 0xBE, 0xEF],
        ];
        for v in vectors {
            assert_eq!(
                doc_crc5_bits(v, v.len() * 8),
                crate::protocol::crc5(v),
                "BM1485 doc CRC5 must equal the shipped crate::protocol::crc5 for {v:02X?}"
            );
        }
    }

    #[test]
    fn command_frames_match_the_documented_wire_bytes() {
        // bm1485.md:73-81 + :54-61. Lengths and fixed fields are the pin;
        // the CRC trailer comes from the shared engine.
        let inactive = chain_inactive_frame();
        assert_eq!(inactive.len(), 5);
        assert_eq!(&inactive[..4], &[0x53, 0x04, 0x00, 0x00]);
        assert_eq!(inactive[4], crate::protocol::crc5(&inactive[..4]));

        let set_addr = set_address_frame(0x47);
        assert_eq!(&set_addr[..4], &[0x40, 0x04, 0x47, 0x00]);

        let read_bcast = read_reg_frame(0x00, regs::CHIP_ADDR, true);
        assert_eq!(&read_bcast[..4], &[0x52, 0x04, 0x00, 0x00]);
        let read_single = read_reg_frame(0x0C, regs::HASHRATE, false);
        assert_eq!(&read_single[..4], &[0x42, 0x04, 0x0C, 0x04]);

        // Length byte is 0x04, explicitly NOT the 0x05 of BM1387/BM1397+
        // (bm1485.md:60).
        assert_eq!(CMD_FRAME_LEN_BYTE, 0x04);
        assert_ne!(CMD_FRAME_LEN_BYTE, 0x05);
    }

    #[test]
    fn write_reg_frame_is_nine_bytes_as_the_held_binary_prints() {
        // Corroborated by the stock cgminer format string
        // `Set config reg %02x : %02x%02x%02x%02x%02x%02x%02x%02x%02x` (9).
        let f = write_reg_frame(0x00, regs::MISC_CONTROL, [0x00, 0x1A, 0x00, 0x00], true);
        assert_eq!(f.len(), 9);
        assert_eq!(WRITE_FRAME_LEN_BYTE, 0x08);
        assert_eq!(&f[..8], &[0x51, 0x08, 0x00, 0x18, 0x00, 0x1A, 0x00, 0x00]);
        assert_eq!(f[8], crate::protocol::crc5(&f[..8]));

        let single = write_reg_frame(0x04, regs::TICKET_MASK, [0xDE, 0xAD, 0xBE, 0xEF], false);
        assert_eq!(&single[..4], &[0x41, 0x08, 0x04, 0x14]);
    }

    #[test]
    fn framing_has_no_bm139x_preamble_and_uses_the_scrypt_work_header() {
        // bm1485.md:28 — BM1387-era framing, no 0x55 0xAA preamble; and :38 —
        // work header is 0x20, NOT the 0x21 SHA-256 marker.
        assert_eq!(headers::SEND_WORK, 0x20);
        assert_ne!(headers::SEND_WORK, 0x21);
        for f in [
            chain_inactive_frame(),
            set_address_frame(0),
            read_reg_frame(0, 0, true),
        ] {
            assert_ne!(f[0], 0x55, "BM1485 frames carry no 0x55 0xAA preamble");
            assert_ne!(f[1], 0xAA);
        }
        // Consequently the FPGA BM139X mode bit must stay CLEAR — the one
        // place BM1485 must diverge from bm1489.rs / scrypt_l7.rs.
        let ctrl = Bm1485Driver::new().ctrl_reg_value();
        assert_eq!(
            ctrl & fpga_chain::CTRL_BM139X,
            0,
            "BM1485 is BM1387-era framing; the BM139X mode bit must not be set"
        );
        assert_ne!(ctrl & fpga_chain::CTRL_ENABLE, 0);
    }

    #[test]
    fn register_map_pins_the_addresses_bm1489_inherits() {
        // bm1489.rs:154-181 documents these six as BM1485 inheritance. If a
        // future edit changes either side they must move together.
        assert_eq!(regs::CHIP_ADDR, super::super::bm1489::regs::CHIP_ADDRESS);
        assert_eq!(
            regs::PLL_PARAMETER,
            super::super::bm1489::regs::PLL0_PARAMETER
        );
        assert_eq!(regs::HCN, super::super::bm1489::regs::HASH_COUNTING);
        assert_eq!(regs::TICKET_MASK, super::super::bm1489::regs::TICKET_MASK);
        assert_eq!(regs::MISC_CONTROL, super::super::bm1489::regs::MISC_CONTROL);
        assert_eq!(regs::CORE_CMD_IN, super::super::bm1489::regs::CORE_REG_CTRL);

        // Full-map spot checks unique to BM1485 (bm1485.md:120-139).
        assert_eq!(regs::HASHRATE, 0x04);
        assert_eq!(regs::SNO, 0x0C);
        assert_eq!(regs::SECURITY_IIC, 0x20);
        assert_eq!(regs::MEMORY_STATUS, 0x38);
        assert_eq!(regs::CORE_RESP_OUT, 0x40);
        assert_eq!(regs::EXT_TEMP_SENSOR, 0x44);
    }

    // ---- FAIL-CLOSED SURFACES ----

    #[test]
    fn addr_stride_is_unresolved_and_fails_closed() {
        assert_eq!(DOC_ADDR_STRIDE_L3PLUS, 1, "bm1485.md:206 claims stride 1");
        // ...but the four-jig bucket rule gives stride 2 for a 72-chip chain.
        let err = addr_stride_plan(DEFAULT_CHIPS_PER_CHAIN_L3PLUS).expect_err("must fail closed");
        assert!(err.to_string().contains("UNRESOLVED"));
    }

    #[test]
    fn pll_params_refuses_to_encode_a_register_value() {
        let cfg = Bm1485Driver::new().pll_params(L3PLUS_NAMEPLATE_FREQ_MHZ);
        // The divider solution is real arithmetic from bm1485.md:189...
        assert!(cfg.fb_div >= FB_DIV_MIN && cfg.fb_div <= FB_DIV_MAX);
        assert!(cfg.ref_div >= 1 && cfg.post_div1 >= 1 && cfg.post_div2 >= 1);
        let solved = CLKI_MHZ * cfg.fb_div as f64
            / (cfg.ref_div as f64 * cfg.post_div1 as f64 * cfg.post_div2 as f64);
        assert!(
            (solved - L3PLUS_NAMEPLATE_FREQ_MHZ as f64).abs() < 1.0,
            "384 MHz must be representable: got {solved}"
        );
        // ...but the register word is NOT encoded. `0` leaves no PLLEN bit
        // set, so even an erroneous write cannot command a clock.
        assert_eq!(cfg.reg_value, PLL_REG_VALUE_UNRESOLVED);
        assert_eq!(
            cfg.reg_value, 0,
            "BM1485 PLL_PARAMETER bit layout is unspecified in every held \
             source; the sentinel must stay inert"
        );
    }

    #[test]
    fn nonce_decode_refuses_between_two_competing_layouts() {
        let d = Bm1485Driver::new();
        assert_eq!(d.response_length(), 7);
        assert_eq!(RESPONSE_BYTES, 7);
        // Both candidate layouts are 7 bytes, so length alone cannot decide.
        assert_ne!(
            NonceFieldLayout::DocHeaderNonceAddrCrc,
            NonceFieldLayout::BinaryNonceWcDiffCrc
        );
        // `NonceResult` has no `Debug`, so match instead of `expect_err`.
        match d.decode_nonce(&[0xDEAD_BEEF, 0x0000_0100]) {
            Ok(_) => panic!("decode_nonce must refuse rather than mis-attribute"),
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("refused"), "{msg}");
                assert!(msg.contains("chip_addr") && msg.contains("wc"), "{msg}");
            }
        }
    }

    #[test]
    fn every_reachable_fail_closed_surface_refuses() {
        // The surfaces a unit test can actually reach without a HAL. The
        // FpgaChain/PicController-taking methods (`init_chain`,
        // `set_frequency`, `set_voltage`, `send_work`) cannot be constructed
        // here; their refusal is enforced by the Scaffold registry tier in
        // `drivers/mod.rs` plus code review of this file.
        //
        // NOTE for future edits: `set_voltage` returns `Err`, deliberately
        // UNLIKE bm1489.rs / scrypt_l7.rs which return `Ok(())`. Those chips
        // are genuinely PIC-less (NoPic / ISL68127); BM1485 has a real
        // PIC16F1704 @ I2C 0x55 (bm1485.md:246), so a no-op success would tell
        // a caller a DAC write landed when nothing happened. Do not
        // "harmonise" it with its siblings.
        let d = Bm1485Driver::new();
        assert!(operational_baud_plan().is_err());
        assert!(addr_stride_plan(DEFAULT_CHIPS_PER_CHAIN_L3PLUS).is_err());
        assert!(d.decode_nonce(&[0, 0]).is_err(), "decode_nonce must refuse");
    }

    #[test]
    fn ticket_mask_is_monotone_and_does_not_underflow() {
        let d = Bm1485Driver::new();
        assert_eq!(d.ticket_mask(256), 255);
        assert_eq!(d.ticket_mask(0), 0);
        assert_eq!(d.ticket_mask(1), 0);
    }

    #[test]
    fn baud_reg_value_does_not_underflow_or_divide_by_zero() {
        let d = Bm1485Driver::new();
        assert_eq!(d.baud_reg_value(115_200, 100_000_000), 53);
        assert_eq!(d.baud_reg_value(50_000_000, 25_000_000), 0);
        // target_baud = 0 must not panic (`.max(1)` guard).
        assert_eq!(d.baud_reg_value(0, 25_000_000), 1_562_499);
    }
}
