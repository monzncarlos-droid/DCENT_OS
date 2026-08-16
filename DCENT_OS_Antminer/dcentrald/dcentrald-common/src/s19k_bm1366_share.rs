//! BM1366 UART nonce → share reconstruction (ESP-Miner `BM1366_process_work`).
//!
//! Pure. Does **not** submit, open UART, or claim accepted shares.
//! Job CRC5 is **not** a drop condition (S21 comparative trailer ≠ init 0x1B).
//!
//! Address interval is AML **2** (desk 11g). Do not use Bitaxe `256/N`.

use crate::s19k_bm1366_uart_rx::{
    admit_fill_work_id_tx_rx_correlate, asic_index_from_nonce_be, chip_addr_from_nonce_be,
    classify_bm1366_uart_rx, core_id_from_nonce_be, S19kUartRxKind, S19kUartRxObservation,
    BM1366_JOB_ID_MASK, BM1366_SMALL_CORE_MASK, BM1366_UART_RESP_BODY_LEN, UART_RESP_LEN,
    UART_RESP_PREAMBLE,
};


/// BIP320 version-roll positions 13..28 (`VERSION_ROLLING_STRATUM_BIP320_MASK`).
/// Do not use the 12-bit mask that drops bits 13..16 (`version_be` low nibble);
/// that would corrupt `serial_rolled_version` after `version_bits >> 13`.
pub const BM1366_VERSION_ROLL_SHIFT: u32 = 13;
pub const BM1366_VERSION_ROLL_MASK: u32 = crate::VERSION_ROLLING_STRATUM_BIP320_MASK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBm1366Share {
    pub job_id: u8,
    pub small_core: u8,
    pub midstate_num: u8,
    pub nonce_be: u32,
    /// Wire/submit nonce (LE interpret of the same 4 bytes).
    pub nonce_le: u32,
    pub version_bits: u32,
    pub rolled_version: u32,
    pub chip_addr: u8,
    pub asic_index: u8,
    pub core_id: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kShareError {
    NotJobNonce,
    JobIdMismatch { observed: u8, expected_mask: u8 },
}

/// Reconstruct rolled version: `base | (version_be << 13)`.
///
/// Braiins `FUN_0091c0a0` WorkResponse version is **not** this 16-bit BIP320
/// field: it AND-masks `version_be` to `((1<<midstate_log)-1)` via
/// `FUN_00bf2478`. Fill midstates=1 ⇒ that field is 0. : the five
/// UART callers plus `FUN_00bf6c2c` do **not** `LSL #13` / build `0x1FFFE000`.
/// Keep this ESP/BIP320 reconstruct for pool submit; see
/// `s19k_braiins_uart_version_bits`.
pub fn reconstruct_rolled_version(base_version: u32, version_be: u16) -> u32 {
    let bits = (u32::from(version_be) << BM1366_VERSION_ROLL_SHIFT) & BM1366_VERSION_ROLL_MASK;
    (base_version & !BM1366_VERSION_ROLL_MASK) | bits
}

/// Parse a job nonce without a job-id match (observe / first-look).
pub fn parse_bm1366_uart_share(
    frame: &[u8],
    base_version: u32,
) -> Result<S19kBm1366Share, S19kShareError> {
    let kind = classify_bm1366_uart_rx(frame).map_err(|_| S19kShareError::NotJobNonce)?;
    let S19kUartRxKind::JobNonce { job_id, .. } = kind else {
        return Err(S19kShareError::NotJobNonce);
    };
    qualify_bm1366_job_nonce(kind, job_id, base_version)
}

/// HAL nonce path delivers the 9-byte body (preamble already stripped).
pub fn parse_bm1366_share_from_body(
    body: &[u8],
    base_version: u32,
) -> Result<S19kBm1366Share, S19kShareError> {
    if body.len() < 9 {
        return Err(S19kShareError::NotJobNonce);
    }
    let mut frame = [0u8; 11];
    frame[0] = 0xAA;
    frame[1] = 0x55;
    frame[2..11].copy_from_slice(&body[..9]);
    parse_bm1366_uart_share(&frame, base_version)
}

/// A nonce job_id must hit an outstanding `WorkHistoryRing` slot.
/// `parse_bm1366_share_from_body` cannot do this — it only sees the frame.
pub fn admit_s19k_share_job_id_in_history(
    history_slot_occupied: bool,
    observed_job_id: u8,
) -> Result<u8, S19kShareError> {
    let id = observed_job_id & BM1366_JOB_ID_MASK;
    if !history_slot_occupied {
        return Err(S19kShareError::JobIdMismatch {
            observed: id,
            expected_mask: BM1366_JOB_ID_MASK,
        });
    }
    Ok(id)
}

/// Braiins fill RX: history key is `job_byte >> fill_log` (log 0 ⇒ raw byte).
/// ESP `id & 0xF8` is a different dialect — see [`refuse_esp_step8_as_braiins_fill_registry`].
pub fn admit_s19k_braiins_fill_share_job_id_in_history(
    history_slot_occupied: bool,
    observed_work_id: u8,
) -> Result<u8, S19kShareError> {
    if !history_slot_occupied {
        return Err(S19kShareError::JobIdMismatch {
            observed: observed_work_id,
            expected_mask: 0xFF,
        });
    }
    Ok(observed_work_id)
}

/// ESP `+8`/`%128` is 16 in-flight IDs. Braiins fill registry is `0x100>>0=256`.
pub fn refuse_esp_step8_as_braiins_fill_registry(step: u8, mask: u8) -> Result<(), &'static str> {
    if step == crate::s19k_bm1366_wire_b::S19K_WIRE_JOB_ID_STEP && mask == 0x7F {
        return Err(
            "ESP/wire step-8 mask 0x7F is 16 slots; Braiins fill UART registry is 256 (log 0)",
        );
    }
    Ok(())
}

/// ESP `id & 0xF8` drops the low 3 bits Braiins fill log=0 uses as work_id.
pub fn refuse_esp_f8_mask_as_braiins_fill_job_id(raw_job_byte: u8) -> Result<(), &'static str> {
    let masked = raw_job_byte & BM1366_JOB_ID_MASK;
    if masked != raw_job_byte {
        return Err("ESP id&0xF8 drops low 3 bits; Braiins fill log=0 uses the raw job byte as work_id");
    }
    Ok(())
}

/// Same 9-byte HAL body as [`parse_bm1366_share_from_body`], but job_id is
/// the Braiins fill work_id (`raw_byte >> log0`), not `id & 0xF8`.
pub fn parse_bm1366_braiins_fill_share_from_body(
    body: &[u8],
    base_version: u32,
) -> Result<S19kBm1366Share, S19kShareError> {
    let mut share = parse_bm1366_share_from_body(body, base_version)?;
    if body.len() < 6 {
        return Err(S19kShareError::NotJobNonce);
    }
    let raw = body[crate::s19k_bm1366_uart_rx::ESP_RX_REG_OR_JOB_ID_OFF - 2];
    let work_id = crate::s19k_braiins_job::s19k_braiins_uart_work_id_from_rx_job_byte(
        raw,
        crate::s19k_braiins_job::s19k_braiins_fill_midstate_log(),
    )
    .map_err(|_| S19kShareError::NotJobNonce)?;
    share.job_id = work_id as u8;
    let payload_le = u64::from_le_bytes([
        body[0],
        body[1],
        body[2],
        body[3],
        body[4],
        body[5],
        body.get(6).copied().unwrap_or(0),
        body.get(7).copied().unwrap_or(0),
    ]);
    let rev = crate::s19k_braiins_job::s19k_braiins_uart_nonce_arg_from_payload8(payload_le);
    // Fill identity is only defined for engine+0x80 == 1 (bm1398_6x.rs:344).
    share.nonce_be = crate::s19k_braiins_job::s19k_braiins_fill_nonce_word(rev);
    share.nonce_le = share.nonce_be.swap_bytes();
    // Fill midstates=1 ⇒ log 0 ⇒ FUN_0091c0a0 version mask is 0.
    // Do not keep ESP `version_be << 13` BIP320 bits from parse_bm1366_share_from_body.
    let version_be = u16::from_be_bytes([
        body.get(6).copied().unwrap_or(0),
        body.get(7).copied().unwrap_or(0),
    ]);
    let masked = crate::s19k_braiins_job::s19k_braiins_uart_version_bits(
        version_be,
        crate::s19k_braiins_job::s19k_braiins_fill_midstate_log(),
    )
    .map_err(|_| S19kShareError::NotJobNonce)?;
    share.version_bits = u32::from(masked);
    share.rolled_version = base_version;
    // Fill midstates=1 ⇒ only index 0. Do not keep ESP body[4] midstate_num.
    share.midstate_num = 0;
    Ok(share)
}

/// Braiins fill UART version is mask 0. ESP BIP320 `version_be << 13` is a
/// different dialect and will fail `validate_full_header` against packed ver0.
pub fn refuse_esp_bip320_as_braiins_fill_version(src: &str) -> Result<(), &'static str> {
    if src.contains("(share.version_bits >> 13) as u16") {
        return Err(
            "Braiins fill version is mask 0; refuse ESP share.version_bits >> 13 on the fill arm",
        );
    }
    Ok(())
}

/// After a successful fill hunt, do not re-drop on ESP `resp[8] & 0x80`.
/// Hunt already required [`crate::s19k_bm1366_uart_rx::JobNonce`] (trailer bit7).
pub fn refuse_esp_flags_redrop_after_fill_hunt(src: &str) -> Result<(), &'static str> {
    if src.contains("0u16, // fill log 0") && src.contains("resp[8]") {
        // Fill Ok tuple must not pass HAL body[8] as flags after hunt.
        if !src.contains("0x80, // fill hunt") {
            return Err(
                "fill hunt already required JobNonce; refuse ESP resp[8] flags redrop",
            );
        }
    }
    Ok(())
}

/// Fill midstates=1 ⇒ midstate index is 0. ESP `body[4]` is a different dialect.
pub fn refuse_esp_midstate_as_braiins_fill_index(src: &str) -> Result<(), &'static str> {
    if src.contains("share.midstate_num") {
        return Err(
            "Braiins fill midstates=1; refuse ESP share.midstate_num as midstate_idx",
        );
    }
    Ok(())
}

/// Qualify a classified UART job nonce against an expected on-wire job_id.
pub fn qualify_bm1366_job_nonce(
    kind: S19kUartRxKind,
    expected_job_id: u8,
    base_version: u32,
) -> Result<S19kBm1366Share, S19kShareError> {
    let S19kUartRxKind::JobNonce {
        nonce_be,
        midstate_num,
        job_id,
        raw_job_byte: _,
        small_core,
        version_be,
    } = kind
    else {
        return Err(S19kShareError::NotJobNonce);
    };
    let expected = expected_job_id & BM1366_JOB_ID_MASK;
    if job_id != expected {
        return Err(S19kShareError::JobIdMismatch {
            observed: job_id,
            expected_mask: expected,
        });
    }
    Ok(S19kBm1366Share {
        job_id,
        small_core,
        midstate_num,
        nonce_be,
        nonce_le: nonce_be.swap_bytes(),
        version_bits: (u32::from(version_be) << BM1366_VERSION_ROLL_SHIFT) & BM1366_VERSION_ROLL_MASK,
        rolled_version: reconstruct_rolled_version(base_version, version_be),
        chip_addr: chip_addr_from_nonce_be(nonce_be),
        asic_index: asic_index_from_nonce_be(nonce_be),
        core_id: core_id_from_nonce_be(nonce_be),
    })
}

/// Fill log=0: match the raw UART job byte. Do not AND-mask `0xF8` first.
pub fn qualify_bm1366_braiins_fill_from_body(
    body: &[u8],
    expected_work_id: u8,
    base_version: u32,
) -> Result<S19kBm1366Share, S19kShareError> {
    let share = parse_bm1366_braiins_fill_share_from_body(body, base_version)?;
    if share.job_id != expected_work_id {
        return Err(S19kShareError::JobIdMismatch {
            observed: share.job_id,
            expected_mask: expected_work_id,
        });
    }
    Ok(share)
}

/// ESP qualify AND-masks expected with 0xF8. Fill work_id 2 becomes 0.
pub fn refuse_esp_qualify_as_braiins_fill(expected_work_id: u8) -> Result<(), &'static str> {
    if expected_work_id & BM1366_JOB_ID_MASK != expected_work_id {
        return Err("qualify_bm1366_job_nonce masks expected with 0xF8; use fill qualify");
    }
    Ok(())
}

/// Synthetic AA55 job body (9 B) with fill work_id 2 in ESP byte 5. Not live BM1366.
pub const SYNTHETIC_BM1366_FILL_WORK2_BODY: [u8; 9] =
    [0x11, 0x22, 0x33, 0x44, 0x00, 0x02, 0x00, 0x00, 0x80];
/// : constructed fill job_id. Not a live sniff.
pub const S19K_CONSTRUCTED_FILL_JOB_ID: u8 = 0x10;
/// Packed nVersion with bit 13 set so BIP320 strip is observable.
pub const S19K_CONSTRUCTED_FILL_BASE_VERSION: u32 = 0x2000_2000;
pub const S19K_CONSTRUCTED_FILL_PREV: [u8; 32] = [0x11; 32];
pub const S19K_CONSTRUCTED_FILL_MERKLE: [u8; 32] = [0x22; 32];
pub const S19K_CONSTRUCTED_FILL_NTIME: u32 = 0x5C00_0000;
pub const S19K_CONSTRUCTED_FILL_NBITS: u32 = 0x1D00_FFFF;
/// Wire nonce bytes in the constructed 9-byte body.
pub const S19K_CONSTRUCTED_FILL_BODY: [u8; 9] =
    [0x00, 0x11, 0x22, 0x33, 0x00, S19K_CONSTRUCTED_FILL_JOB_ID, 0x00, 0x00, 0x80];
/// Constructed RX job byte with small_core ORed in. Not a live sniff.
pub const S19K_CONSTRUCTED_FILL_SMALL_CORE: u8 = 0x02;
pub const S19K_CONSTRUCTED_FILL_JOB_OR_CORE: u8 =
    S19K_CONSTRUCTED_FILL_JOB_ID | S19K_CONSTRUCTED_FILL_SMALL_CORE;
pub const S19K_CONSTRUCTED_FILL_WORK10_CORE2_BODY: [u8; 9] = [
    0x00,
    0x11,
    0x22,
    0x33,
    0x00,
    S19K_CONSTRUCTED_FILL_JOB_OR_CORE,
    0x00,
    0x00,
    0x80,
];

/// One UART nonce body plus the tty that produced it. Untagged hits
/// (AM2 / uart_trans) leave `path` None.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kSerialRxHit {
    pub path: Option<&'static str>,
    pub body: Vec<u8>,
}

impl S19kSerialRxHit {
    pub fn untagged(body: Vec<u8>) -> Self {
        Self { path: None, body }
    }
}

/// Fill work_id is a `u8`. A 32-deep FIFO can drop a still-valid older slot.
pub const S19K_FILL_TX_SLOTS: usize = 256;

/// Closed fill TX prefix: `55 AA 21 36` + fill job_id.
pub fn s19k_fill_tx_prefix(job_id: u8) -> [u8; 5] {
    let p = crate::s19k_braiins_job::CLOSED_11D_PREFIX;
    [
        p[0],
        p[1],
        p[2],
        p[3],
        crate::s19k_braiins_job::s19k_braiins_fill_job_id(job_id),
    ]
}

/// : tagged body + outstanding `21 36` TX. Not `qualify(parsed.job_id)`.
pub fn hunt_s19k_bm1366_fill_from_tagged_outstanding(
    path: &str,
    body: Option<&[u8]>,
    outstanding_txs: &[Vec<u8>],
) -> Result<S19kBm1366Share, &'static str> {
    let obs = crate::s19k_braiins_chain_discover::observe_s19k_tagged_rx_body(path, body, 10)?;
    match &obs {
        S19kUartRxObservation::Frames { frames, .. }
            if frames
                .iter()
                .any(|kind| matches!(kind, S19kUartRxKind::JobNonce { .. })) => {}
        S19kUartRxObservation::Silence { .. } => {
            return Err("tagged RX silence is not a BM1366 share");
        }
        _ => return Err("tagged RX is not JobNonce (framing/echo/short/chip)"),
    }
    let body = body.filter(|b| !b.is_empty()).ok_or("tagged RX body empty")?;
    if body.len() != BM1366_UART_RESP_BODY_LEN {
        return Err("BM1366 fill body must be 9");
    }
    if outstanding_txs.is_empty() {
        return Err("no outstanding 21 36 TX to correlate");
    }
    let mut rx = [0u8; UART_RESP_LEN];
    rx[0] = UART_RESP_PREAMBLE[0];
    rx[1] = UART_RESP_PREAMBLE[1];
    rx[2..].copy_from_slice(body);
    if !outstanding_txs
        .iter()
        .any(|tx| admit_fill_work_id_tx_rx_correlate(tx, &rx).is_ok())
    {
        return Err("RX job_id does not correlate with any outstanding 21 36 TX");
    }
    parse_bm1366_braiins_fill_share_from_body(body, 0)
        .map_err(|_| "fill parse failed after TX/RX correlate")
}

/// : outstanding `21 36` TX indexed by sent fill job_id.
/// Replacing a slot overwrites that job_id only. Wrap of a 32-deep FIFO
/// cannot drop a still-valid older slot.
#[derive(Clone, Debug)]
pub struct S19kOutstandingFillTx {
    slots: Vec<Option<Vec<u8>>>,
}

impl Default for S19kOutstandingFillTx {
    fn default() -> Self {
        Self::new()
    }
}

impl S19kOutstandingFillTx {
    pub fn new() -> Self {
        Self {
            slots: vec![None; S19K_FILL_TX_SLOTS],
        }
    }

    pub fn insert_wire(&mut self, wire: Vec<u8>) -> Result<u8, &'static str> {
        let job_id = s19k_fill_job_id_from_tx_wire(&wire)?;
        self.slots[usize::from(job_id)] = Some(wire);
        Ok(job_id)
    }

    pub fn get(&self, job_id: u8) -> Option<&[u8]> {
        self.slots[usize::from(job_id)].as_deref()
    }

    pub fn clear(&mut self) {
        for slot in &mut self.slots {
            *slot = None;
        }
    }

    pub fn occupied(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }
}

/// Constructed RX job byte: `work_id | (small_core & 0x07)`.
pub fn s19k_fill_job_byte_or_small_core(work_id: u8, small_core: u8) -> u8 {
    work_id | (small_core & BM1366_SMALL_CORE_MASK)
}

/// Braiins fill log 0: `FUN_0091c0a0` work_id is `payload[5] >> 0` = raw byte.
/// ESP `id & 0xF8` overlay is a different dialect.
pub fn s19k_fill_lookup_tx<'a>(
    raw_job_byte: u8,
    outstanding: &'a S19kOutstandingFillTx,
) -> Result<(&'a [u8], u8), &'static str> {
    if let Some(tx) = outstanding.get(raw_job_byte) {
        return Ok((tx, raw_job_byte));
    }
    Err("no outstanding 21 36 TX in that raw fill job-id slot")
}

/// ESP-Miner overlay. Not FUN_0091c0a0. Not production fill hunt.
pub fn s19k_fill_lookup_tx_esp_overlay_experimental<'a>(
    raw_job_byte: u8,
    outstanding: &'a S19kOutstandingFillTx,
) -> Result<(&'a [u8], u8), &'static str> {
    if let Some(tx) = outstanding.get(raw_job_byte) {
        return Ok((tx, raw_job_byte));
    }
    let overlay = raw_job_byte & BM1366_JOB_ID_MASK;
    if overlay != raw_job_byte {
        if let Some(tx) = outstanding.get(overlay) {
            return Ok((tx, overlay));
        }
    }
    Err("no outstanding 21 36 TX in that ESP overlay job-id slot")
}

pub fn refuse_s19k_fill_overlay_f8_as_fun_0091c0a0() -> Result<(), &'static str> {
    Err(
        "FUN_0091c0a0 fill work_id is payload[5]>>log; log 0 is the raw byte, not id&0xF8 overlay",
    )
}

pub fn admit_s19k_fill_lookup_uses_raw_job_byte(
    raw_job_byte: u8,
    resolved: u8,
) -> Result<(), &'static str> {
    if raw_job_byte == resolved {
        return Ok(());
    }
    Err("Braiins fill lookup must resolve the raw job byte, not an ESP 0xF8 overlay")
}

pub fn admit_s19k_production_fill_lookup_is_raw(src: &str) -> Result<(), &'static str> {
    let start = src
        .find("pub fn s19k_fill_lookup_tx<")
        .ok_or("missing s19k_fill_lookup_tx")?;
    let win = src.get(start..start.saturating_add(450)).unwrap_or("");
    if win.contains("raw_job_byte & BM1366_JOB_ID_MASK") {
        return Err("production fill lookup must not overlay id&0xF8");
    }
    if !win.contains("outstanding.get(raw_job_byte)") {
        return Err("production fill lookup must index the raw job byte");
    }
    Ok(())
}

pub fn s19k_fill_job_id_from_tx_wire(wire: &[u8]) -> Result<u8, &'static str> {
    if wire.len() < 5 {
        return Err("TX shorter than prefix+job_id");
    }
    if wire[0..4] != crate::s19k_braiins_job::CLOSED_11D_PREFIX {
        return Err("outstanding TX must be 55 AA 21 36");
    }
    Ok(wire[4])
}

/// Hunt using the job-id slot, not a FIFO scan that can wrap away the TX.
pub fn hunt_s19k_bm1366_fill_from_tagged_slot(
    path: &str,
    body: Option<&[u8]>,
    outstanding: &S19kOutstandingFillTx,
) -> Result<S19kBm1366Share, &'static str> {
    crate::s19k_braiins_chain_discover::refuse_s3_rx_as_fill_hunt(path)?;
    let obs = crate::s19k_braiins_chain_discover::observe_s19k_tagged_rx_body(path, body, 10)?;
    match &obs {
        S19kUartRxObservation::Frames { frames, .. }
            if frames
                .iter()
                .any(|kind| matches!(kind, S19kUartRxKind::JobNonce { .. })) => {}
        S19kUartRxObservation::Silence { .. } => {
            return Err("tagged RX silence is not a BM1366 share");
        }
        _ => return Err("tagged RX is not JobNonce (framing/echo/short/chip)"),
    }
    let body = body.filter(|b| !b.is_empty()).ok_or("tagged RX body empty")?;
    if body.len() != BM1366_UART_RESP_BODY_LEN {
        return Err("BM1366 fill body must be 9");
    }
    let mut share = parse_bm1366_braiins_fill_share_from_body(body, 0)
        .map_err(|_| "fill parse failed before slot lookup")?;
    let raw = body[crate::s19k_bm1366_uart_rx::ESP_RX_REG_OR_JOB_ID_OFF - 2];
    let (tx, resolved) = s19k_fill_lookup_tx(raw, outstanding)?;
    share.job_id = resolved;
    let mut rx = [0u8; UART_RESP_LEN];
    rx[0] = UART_RESP_PREAMBLE[0];
    rx[1] = UART_RESP_PREAMBLE[1];
    rx[2..].copy_from_slice(body);
    admit_fill_work_id_tx_rx_correlate(tx, &rx)?;
    Ok(share)
}

/// A 32-deep FIFO is not an S19k outstanding-TX table.
pub fn refuse_s19k_fifo32_wrap_as_outstanding_table() -> Result<(), &'static str> {
    Err(
        "32-deep FIFO wrap can drop an older still-valid fill job_id; index by sent job-id slot (256)",
    )
}

/// UART send queue must cover the 256-slot fill outstanding table.
pub fn admit_s19k_uart_queue_covers_fill_slots(depth: usize) -> Result<(), &'static str> {
    if depth < S19K_FILL_TX_SLOTS {
        return Err(
            "UART work queue shallower than 256 fill slots drops 21 36 still held in outstanding",
        );
    }
    Ok(())
}

pub fn refuse_s19k_uart_queue16_as_fill_depth(depth: usize) -> Result<(), &'static str> {
    if depth == 16 {
        return Err("16-deep UART queue is not the 256-slot fill outstanding table");
    }
    Ok(())
}

/// Production `run()` must select BM1366_SERIAL_WORK_QUEUE_DEPTH, not default 16.
pub fn admit_s19k_production_bm1366_queue_covers_fill_slots(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("let work_queue_depth = if is_bm1362") else {
        return Err("missing work_queue_depth selection");
    };
    let win = src.get(start..start.saturating_add(500)).unwrap_or("");
    if !win.contains("} else if is_bm1366 {") {
        return Err("BM1366 must select its own work_queue_depth");
    }
    if !win.contains("BM1366_SERIAL_WORK_QUEUE_DEPTH") {
        return Err("BM1366 work_queue_depth must be BM1366_SERIAL_WORK_QUEUE_DEPTH");
    }
    if win.contains("is_bm1366 {\n            DEFAULT_SERIAL_WORK_QUEUE_DEPTH") {
        return Err("BM1366 must not use DEFAULT_SERIAL_WORK_QUEUE_DEPTH 16");
    }
    Ok(())
}

/// Track-1 must not OR the Braiins handoff into thermal_proof_present.
pub fn admit_s19k_track1_thermal_handoff_unowned(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("let thermal_proof_present =") else {
        return Err("missing thermal_proof_present");
    };
    let after = src.get(start..).unwrap_or("");
    let end = after.find(';').unwrap_or(400);
    let win = after.get(..end).unwrap_or("");
    if win.contains("braiins_bm1366_passthrough_handoff") {
        return Err("thermal_proof_present must not include Braiins handoff as Ready");
    }
    if !src.contains("ThermalSafetyState::HandoffUnowned") {
        return Err("Track-1 must set HandoffUnowned, not invent Ready");
    }
    if !src.contains("thermal HandoffUnowned (not Ready)") {
        return Err("Track-1 must log HandoffUnowned is not Ready");
    }
    Ok(())
}

pub fn refuse_s19k_track1_handoff_as_thermal_ready() -> Result<(), &'static str> {
    Err("Track-1 Braiins passthrough is thermal HandoffUnowned, not Ready")
}

/// BM1366 must TX-before-RX so the 256-deep queue drains before VTIME read.
pub fn admit_s19k_production_bm1366_tx_before_rx(src: &str) -> Result<(), &'static str> {
    if !src.contains("let tx_before_rx = is_bm1362 || is_bm1366") {
        return Err("BM1366 must TX-before-RX with BM1362");
    }
    Ok(())
}

/// Leftover init_bm1366_chain must env-gate experimental use.
pub fn admit_s19k_init_bm1366_requires_experimental_env(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1366_chain(") else {
        return Err("missing init_bm1366_chain");
    };
    let win = src.get(start..start.saturating_add(2500)).unwrap_or("");
    if !win.contains("DCENT_S19K_EXPERIMENTAL_INIT_BM1366") {
        return Err("leftover init_bm1366_chain must require DCENT_S19K_EXPERIMENTAL_INIT_BM1366=1");
    }
    Ok(())
}

/// HAL body-7 *wire* cut of a constructed fill nonce (AA 55 + 7) is framing, not a share.
pub fn refuse_constructed_fill_hal_body7_wire_as_share(
    path: &str,
    raw_job: u8,
    outstanding: &[Vec<u8>],
) -> Result<(), &'static str> {
    use crate::s19k_bm1366_uart_rx::{bm1366_fill_job_nonce_uart, s19k_hal_body7_wire_cut};
    let rx = bm1366_fill_job_nonce_uart(raw_job);
    let cut = s19k_hal_body7_wire_cut(&rx).ok_or("constructed fill nonce shorter than body-7 cut")?;
    match hunt_s19k_bm1366_fill_from_tagged_outstanding(path, Some(cut), outstanding) {
        Ok(_) => Ok(()),
        Err(e)
            if e.contains("framing")
                || e.contains("not JobNonce")
                || e.contains("must be 9") =>
        {
            Err("constructed fill HAL body-7 wire cut is framing, not a share or Silence")
        }
        Err(_) => Ok(()),
    }
}

/// HAL `try_extract_frame(7)` **body** of a constructed fill nonce.
/// Distinct from W330's 9-byte *wire* cut (`AA 55`+7).
pub fn refuse_constructed_fill_hal_body7_extract_as_share(
    path: &str,
    raw_job: u8,
    slots: &S19kOutstandingFillTx,
) -> Result<(), &'static str> {
    use crate::s19k_bm1366_uart_rx::{bm1366_fill_job_nonce_uart, extract_s19k_aa55_bodies};
    let rx = bm1366_fill_job_nonce_uart(raw_job);
    let bodies = extract_s19k_aa55_bodies(&rx, 7);
    if bodies.len() != 1 || bodies[0].len() != 7 {
        return Ok(());
    }
    match hunt_s19k_bm1366_fill_from_tagged_slot(path, Some(bodies[0].as_slice()), slots) {
        Ok(_) => Ok(()),
        Err(e)
            if e.contains("must be 9")
                || e.contains("framing")
                || e.contains("not JobNonce") =>
        {
            Err("constructed fill HAL body-7 extract is not a share")
        }
        Err(_) => Ok(()),
    }
}

/// Same constructed nonce, HAL body-9 extract, must hunt against the job-id slot.
pub fn admit_constructed_fill_hal_body9_extract_hunts(
    path: &str,
    raw_job: u8,
    slots: &S19kOutstandingFillTx,
) -> Result<S19kBm1366Share, &'static str> {
    use crate::s19k_bm1366_uart_rx::{
        bm1366_fill_job_nonce_uart, extract_s19k_hal_bm1366_bodies,
    };
    let rx = bm1366_fill_job_nonce_uart(raw_job);
    let bodies = extract_s19k_hal_bm1366_bodies(&rx);
    if bodies.len() != 1 || bodies[0].len() != BM1366_UART_RESP_BODY_LEN {
        return Err("HAL body-9 extract of constructed fill nonce must be one 9-byte body");
    }
    hunt_s19k_bm1366_fill_from_tagged_slot(path, Some(bodies[0].as_slice()), slots)
}

/// Two-frame body-7 extract: neither 7-byte body is a share. Residue is not a frame.
pub fn refuse_s19k_body7_two_frame_extract_as_shares(
    path: &str,
    slots: &S19kOutstandingFillTx,
) -> Result<(), &'static str> {
    use crate::s19k_bm1366_uart_rx::{
        admit_s19k_body7_two_frame_leaves_residue, admit_s19k_body9_two_frame_no_residue,
        bm1366_chip_address_uart, bm1366_fill_job_nonce_uart, refuse_s19k_body7_residue_as_frame,
    };
    let mut stream = Vec::with_capacity(22);
    stream.extend_from_slice(&bm1366_fill_job_nonce_uart(2));
    stream.extend_from_slice(&bm1366_chip_address_uart(0));
    let (bodies, residue) = admit_s19k_body7_two_frame_leaves_residue(&stream)?;
    if refuse_s19k_body7_residue_as_frame(&residue).is_ok() {
        return Ok(());
    }
    for body in &bodies {
        match hunt_s19k_bm1366_fill_from_tagged_slot(path, Some(body.as_slice()), slots) {
            Ok(_) => return Ok(()),
            Err(e)
                if e.contains("must be 9")
                    || e.contains("framing")
                    || e.contains("not JobNonce") => {}
            Err(_) => return Ok(()),
        }
    }
    let nine = admit_s19k_body9_two_frame_no_residue(&stream)?;
    if nine[0].len() != BM1366_UART_RESP_BODY_LEN {
        return Ok(());
    }
    Err("body-7 two-frame extract is not dual shares; body-9 leaves no residue")
}

/// Body-7 cut of `first_job`, then body-9 recovery of `next_job` hunts that slot.
pub fn admit_s19k_body7_then_body9_next_frame_hunts(
    path: &str,
    first_job: u8,
    next_job: u8,
    slots: &S19kOutstandingFillTx,
) -> Result<S19kBm1366Share, &'static str> {
    use crate::s19k_bm1366_uart_rx::{
        admit_s19k_body7_residue_then_body9_recovers_next, bm1366_fill_job_nonce_uart,
    };
    let first = bm1366_fill_job_nonce_uart(first_job);
    let next = bm1366_fill_job_nonce_uart(next_job);
    let recovered = admit_s19k_body7_residue_then_body9_recovers_next(&first, &next)?;
    hunt_s19k_bm1366_fill_from_tagged_slot(path, Some(recovered.as_slice()), slots)
}

pub fn refuse_tautological_fill_qualify_source(src: &str) -> Result<(), &'static str> {
    if src.contains("qualify_bm1366_braiins_fill_from_body(&resp[..9], share.job_id") {
        return Err("production must not qualify fill against the just-parsed job_id");
    }
    Ok(())
}

/// Bitcoin 80-byte header the fill hunt + midstate0 OR must produce.
pub fn s19k_bm1366_fill_header80(
    rolled_version: u32,
    prev: &[u8; 32],
    merkle: &[u8; 32],
    ntime: u32,
    nbits: u32,
    nonce: u32,
) -> [u8; 80] {
    let mut header = [0u8; 80];
    header[0..4].copy_from_slice(&rolled_version.to_le_bytes());
    header[4..36].copy_from_slice(prev);
    header[36..68].copy_from_slice(merkle);
    header[68..72].copy_from_slice(&ntime.to_le_bytes());
    header[72..76].copy_from_slice(&nbits.to_le_bytes());
    header[76..80].copy_from_slice(&nonce.to_le_bytes());
    header
}

/// : pack `21 36` → slot hunt → midstate0 OR → 80-byte header.
/// Fill log 0 leaves packed bit 13 in the header. BIP320 strip must not.
pub fn admit_s19k_constructed_fill_hunts_and_headers() -> Result<[u8; 80], &'static str> {
    let wire = crate::s19k_braiins_job::build_s19k_braiins_mining_on_work_wire(
        S19K_CONSTRUCTED_FILL_JOB_ID,
        S19K_CONSTRUCTED_FILL_BASE_VERSION,
        S19K_CONSTRUCTED_FILL_PREV,
        S19K_CONSTRUCTED_FILL_MERKLE,
        S19K_CONSTRUCTED_FILL_NTIME,
        S19K_CONSTRUCTED_FILL_NBITS,
    );
    if wire[0..4] != crate::s19k_braiins_job::CLOSED_11D_PREFIX {
        return Err("constructed TX must be 55 AA 21 36");
    }
    let mut slots = S19kOutstandingFillTx::new();
    slots
        .insert_wire(wire.to_vec())
        .map_err(|_| "constructed TX insert")?;
    let share = hunt_s19k_bm1366_fill_from_tagged_slot(
        "/dev/ttyS1",
        Some(&S19K_CONSTRUCTED_FILL_BODY),
        &slots,
    )?;
    if share.job_id != S19K_CONSTRUCTED_FILL_JOB_ID {
        return Err("constructed hunt job_id");
    }
    if share.version_bits != 0 {
        return Err("fill log 0 version mask must be 0");
    }
    if share.midstate_num != 0 {
        return Err("fill midstates=1 index must be 0");
    }
    let rolled = crate::s19k_braiins_job::s19k_braiins_midstate0_version(
        S19K_CONSTRUCTED_FILL_BASE_VERSION,
        share.version_bits as u16,
    );
    if rolled != S19K_CONSTRUCTED_FILL_BASE_VERSION {
        return Err("fill vbits 0 must OR packed ver0 unchanged");
    }
    let stripped = crate::s19k_braiins_job::refuse_bip320_strip_as_braiins_fill_ver0(
        S19K_CONSTRUCTED_FILL_BASE_VERSION,
        0,
    );
    if stripped == rolled {
        return Err("packed bit 13 must distinguish midstate0 OR from BIP320 strip");
    }
    let header = s19k_bm1366_fill_header80(
        rolled,
        &S19K_CONSTRUCTED_FILL_PREV,
        &S19K_CONSTRUCTED_FILL_MERKLE,
        S19K_CONSTRUCTED_FILL_NTIME,
        S19K_CONSTRUCTED_FILL_NBITS,
        share.nonce_le,
    );
    if header[0..4] != S19K_CONSTRUCTED_FILL_BASE_VERSION.to_le_bytes() {
        return Err("header version must be packed ver0, not BIP320-stripped");
    }
    Ok(header)
}

/// Asymmetric stratum prev. `[0x11; 32]` is invariant under both reverses.
pub const S19K_STRATUM_PREV_ASYM: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
    0x1E, 0x1F,
];

/// WorkBuilder / `serial_build_header` prev: per-word byte swap of stratum.
pub fn s19k_workentry_prev_from_stratum(stratum: &[u8; 32]) -> [u8; 32] {
    let mut out = *stratum;
    for chunk in out.chunks_exact_mut(4) {
        chunk.reverse();
    }
    out
}

/// Fill header prev is WorkEntry format, not stratum and not 21 36 wire order.
pub fn admit_s19k_fill_header_uses_workentry_prev_not_wire() -> Result<[u8; 80], &'static str> {
    let stratum = S19K_STRATUM_PREV_ASYM;
    let workentry = s19k_workentry_prev_from_stratum(&stratum);
    let wire = crate::s19k_braiins_job::reverse_32bit_words(&workentry);
    if workentry == stratum {
        return Err("asymmetric prev must change under per-word endian");
    }
    if wire == workentry || wire == stratum {
        return Err("21 36 word-order reverse must differ from WorkEntry and stratum prev");
    }
    let merkle = S19K_STRATUM_PREV_ASYM;
    let merkle_wire = crate::s19k_braiins_job::reverse_32bit_words(&merkle);
    let header = s19k_bm1366_fill_header80(
        S19K_CONSTRUCTED_FILL_BASE_VERSION,
        &workentry,
        &merkle,
        S19K_CONSTRUCTED_FILL_NTIME,
        S19K_CONSTRUCTED_FILL_NBITS,
        0,
    );
    if header[4..36] != workentry {
        return Err("fill header prev must be WorkEntry / serial_build_header prev");
    }
    if header[4..36] == stratum {
        return Err("fill header must not use raw stratum prev");
    }
    if header[4..36] == wire {
        return Err("fill header must not use 21 36 wire word-order prev");
    }
    if header[36..68] != merkle {
        return Err("fill header merkle must be WorkEntry raw merkle");
    }
    if merkle == merkle_wire {
        return Err("need merkle that changes under word-order reverse");
    }
    Ok(header)
}

pub fn refuse_s19k_stratum_prev_as_fill_header() -> Result<(), &'static str> {
    Err("stratum prev is not WorkEntry header prev (reverse_endianness_per_word)")
}

pub fn refuse_s19k_wire_word_reverse_as_fill_header() -> Result<(), &'static str> {
    Err("21 36 reverse_32bit_words prev is the pack wire field, not serial_build_header")
}

/// Production `serial_build_header` copies WorkEntry prev/merkle, not wire reverse.
pub fn admit_s19k_production_header_uses_workentry_prev(
    src: &str,
) -> Result<(), &'static str> {
    let Some(fn_start) = src.find("fn serial_build_header(") else {
        return Err("serial_build_header missing");
    };
    let window = src[fn_start..]
        .split("fn serial_full_header_hash_be(")
        .next()
        .ok_or("serial_build_header window missing")?;
    if !window.contains("&entry.prev_block_hash") {
        return Err("serial_build_header must use WorkEntry prev");
    }
    if !window.contains("&entry.merkle_root") {
        return Err("serial_build_header must use WorkEntry merkle");
    }
    if window.contains("reverse_32bit_words(&entry.prev_block_hash)") {
        return Err("serial_build_header must not word-order-reverse WorkEntry prev");
    }
    Ok(())
}

pub fn refuse_constructed_fill_header_as_bip320_strip(header: &[u8; 80]) -> Result<(), &'static str> {
    let stripped = crate::s19k_braiins_job::refuse_bip320_strip_as_braiins_fill_ver0(
        S19K_CONSTRUCTED_FILL_BASE_VERSION,
        0,
    );
    if header[0..4] == stripped.to_le_bytes() {
        return Err("constructed header used BIP320 strip; fill packed ver0 required");
    }
    Ok(())
}

/// Production BM1366 hunt must pass the 9-byte UART body, not HAL default 7.
pub fn admit_s19k_production_hunt_uses_body9(src: &str) -> Result<(), &'static str> {
    if !src.contains("hunt_s19k_bm1366_fill_from_tagged_slot") {
        return Err("production hunter must call hunt_s19k_bm1366_fill_from_tagged_slot");
    }
    if !src.contains("Some(&resp[..9])") {
        return Err("production BM1366 hunt must pass Some(&resp[..9])");
    }
    if src.contains("Some(&resp[..7])") {
        return Err("production must not hunt HAL body-7 Some(&resp[..7])");
    }
    if !src.contains("BM1366_UART_RESP_BODY_LEN") {
        return Err("production must name BM1366_UART_RESP_BODY_LEN");
    }
    Ok(())
}

pub fn refuse_s19k_production_bm1366_hunt_as_hal_body7() -> Result<(), &'static str> {
    Err("production BM1366 must hunt resp[..9] / BM1366_UART_RESP_BODY_LEN, not HAL DEFAULT 7")
}

/// Track-1 must `set_response_len(resp_body_len)` before the first GetAddress read.
pub fn admit_s19k_production_sets_body_before_first_read(src: &str) -> Result<(), &'static str> {
    let Some(open) = src
        .find("SerialChainBackend::open_passthrough_bm1366(i as u8, path)")
        .or_else(|| src.find("SerialChainBackend::open_passthrough(i as u8, path)"))
    else {
        return Err("missing Track-1 open_passthrough");
    };
    let win = src.get(open..open.saturating_add(1800)).unwrap_or("");
    let Some(set_at) = win.find("s.set_response_len(resp_body_len)") else {
        return Err("Track-1 must set_response_len after open_passthrough");
    };
    if let Some(get_at) = win.find("send_get_address") {
        if get_at < set_at {
            return Err("Track-1 must set_response_len before send_get_address");
        }
    }
    Ok(())
}

/// HAL must expose a BM1366 passthrough open that sets body 9 before return.
pub fn admit_s19k_hal_open_passthrough_bm1366(src: &str) -> Result<(), &'static str> {
    if !src.contains("fn open_passthrough_bm1366") {
        return Err("HAL must expose open_passthrough_bm1366");
    }
    if !src.contains("set_response_len(BM1366_UART_RESP_BODY_LEN)") {
        return Err("open_passthrough_bm1366 must set BM1366 body 9 before return");
    }
    Ok(())
}

/// Generic `else if passthrough` must refuse BM1366 before `open_passthrough(0)`.
pub fn admit_s19k_production_refuses_generic_passthrough_for_bm1366(
    src: &str,
) -> Result<(), &'static str> {
    let Some(arm) = src.find("} else if passthrough {") else {
        return Err("missing generic passthrough arm");
    };
    let win = src.get(arm..arm.saturating_add(700)).unwrap_or("");
    if !win.contains("if is_bm1366") {
        return Err("generic passthrough arm must refuse BM1366");
    }
    if !win.contains("open_passthrough_bm1366") {
        return Err("generic passthrough BM1366 refuse must name open_passthrough_bm1366");
    }
    let bail_at = win.find("anyhow::bail!");
    let open0_at = win.find("open_passthrough(0, &serial_device)");
    match (bail_at, open0_at) {
        (Some(b), Some(o)) if b < o => Ok(()),
        _ => Err("generic passthrough must bail BM1366 before open_passthrough(0)"),
    }
}

/// Generic `open_passthrough(0)` is not S19k Track-1.
pub fn refuse_s19k_generic_passthrough0_as_track1() -> Result<(), &'static str> {
    Err("generic open_passthrough(0) is not S19k Track-1; BM1366 must bail before that open")
}

/// Track-1 must not construct generic open_passthrough (DEFAULT 7) for BM1366.
pub fn admit_s19k_production_uses_bm1366_passthrough_open(src: &str) -> Result<(), &'static str> {
    if !src.contains("open_passthrough_bm1366(i as u8, path)") {
        return Err("Track-1 must open via open_passthrough_bm1366");
    }
    if src.contains("SerialChainBackend::open_passthrough(i as u8, path)") {
        return Err("Track-1 must not use generic open_passthrough for BM1366");
    }
    Ok(())
}

/// HAL constructor default 7 is not a valid BM1366 first-read body.
pub fn refuse_hal_default_body7_as_bm1366_first_read(body_len: usize) -> Result<(), &'static str> {
    if body_len == crate::s19k_bm1366_uart_rx::BM139X_HAL_DEFAULT_RESP_BODY_LEN {
        return Err(
            "BM1366 first-read still at HAL DEFAULT_RESP_BODY_LEN 7; set_response_len(9) was skipped",
        );
    }
    Ok(())
}

/// Skipping `open_passthrough_bm1366` leaves first-read at HAL DEFAULT 7.
pub fn refuse_s19k_skip_bm1366_open_first_read_at_7(
    used_bm1366_open: bool,
    body_len: usize,
) -> Result<(), &'static str> {
    if !used_bm1366_open
        && body_len == crate::s19k_bm1366_uart_rx::BM139X_HAL_DEFAULT_RESP_BODY_LEN
    {
        return Err(
            "skipping open_passthrough_bm1366 leaves first-read at HAL DEFAULT 7",
        );
    }
    Ok(())
}

/// Track-1 must `require_bm1366_response_body` before GetAddress / drain.
pub fn admit_s19k_production_requires_body9_before_first_read(
    src: &str,
) -> Result<(), &'static str> {
    let Some(open) = src.find("SerialChainBackend::open_passthrough_bm1366(i as u8, path)")
    else {
        return Err("missing Track-1 open_passthrough_bm1366");
    };
    let win = src.get(open..open.saturating_add(1800)).unwrap_or("");
    let Some(req_at) = win.find("require_bm1366_response_body") else {
        return Err("Track-1 must require_bm1366_response_body after open");
    };
    if let Some(get_at) = win.find("send_get_address") {
        if get_at < req_at {
            return Err("Track-1 must require_bm1366_response_body before send_get_address");
        }
    }
    if let Some(drain_at) = win.find("drain_serial_passthrough_backlog") {
        if drain_at < req_at {
            return Err("Track-1 must require_bm1366_response_body before drain");
        }
    }
    Ok(())
}

/// `init_bm1366_chain` (experimental leftover) must require body 9 before flush.
pub fn admit_s19k_init_bm1366_requires_body9_before_flush(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1366_chain(") else {
        return Err("missing init_bm1366_chain");
    };
    let rest = src.get(start..start.saturating_add(2500)).unwrap_or("");
    let Some(open_at) = rest.find("SerialChainBackend::open(0, serial_device, 115_200)") else {
        return Err("init_bm1366_chain must open at 115200");
    };
    let after_open = rest.get(open_at..).unwrap_or("");
    let Some(req_at) = after_open.find("require_bm1366_response_body") else {
        return Err("init_bm1366_chain must require_bm1366_response_body");
    };
    let Some(flush_at) = after_open.find("flush_io") else {
        return Err("init_bm1366_chain must still flush_io");
    };
    if flush_at < req_at {
        return Err("init_bm1366_chain must require body 9 before flush_io");
    }
    if !after_open.contains("set_response_len(BM1366_UART_RESP_BODY_LEN)") {
        return Err("init_bm1366_chain must set BM1366_UART_RESP_BODY_LEN, not a generic 9");
    }
    Ok(())
}

/// Leftover `init_bm1366_chain` must not broadcast ESP VersionMask 0xA4=0x9000FFFF.
pub fn admit_s19k_init_bm1366_omits_esp_a4(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1366_chain(") else {
        return Err("missing init_bm1366_chain");
    };
    let end = src[start + 1..]
        .find("fn init_bm1370_chain(")
        .map(|i| start + 1 + i)
        .unwrap_or(src.len());
    let win = &src[start..end];
    if win.contains("BM1366_VERSION_MASK_VALUE")
        || win.contains("send_write_reg_broadcast_bm1397plus(0xA4")
    {
        return Err("init_bm1366_chain must not write ESP 0xA4=0x9000FFFF VersionMask");
    }
    Ok(())
}

/// Production `run()` must not call the leftover init_bm1366_chain.
pub fn admit_s19k_production_run_skips_init_bm1366_chain(src: &str) -> Result<(), &'static str> {
    let Some(run_start) = src.find("pub async fn run(&mut self)") else {
        return Err("missing production run()");
    };
    let run_end = src.find("\n#[cfg(test)]\nmod tests {").unwrap_or(src.len());
    if run_end <= run_start {
        return Err("cannot isolate production run()");
    }
    let run = &src[run_start..run_end];
    if run.contains("Self::init_bm1366_chain(") {
        return Err("production run() must not call init_bm1366_chain");
    }
    Ok(())
}

/// NoPic serial observation facade requires BM1368/BM1370, not BM1366.
pub fn admit_s19k_nopic_observation_refuses_bm1366(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn begin_nopic_observation(") else {
        return Err("missing begin_nopic_observation");
    };
    let win = src.get(start..start.saturating_add(1800)).unwrap_or("");
    if !win.contains("AsicProtocolIdentity::Bm1368")
        || !win.contains("AsicProtocolIdentity::Bm1370")
    {
        return Err("NoPic observation must require BM1368/BM1370 identity");
    }
    if win.contains("AsicProtocolIdentity::Bm1366") {
        return Err("NoPic observation must not admit BM1366 identity");
    }
    if !win.contains("NoPic observation requires BM1368/BM1370 identity") {
        return Err("NoPic observation must refuse non-BM1368/1370 identity");
    }
    Ok(())
}

/// Hot-start baud-wake (only BM1366 leftover caller) must set body 9 before spray.
pub fn admit_s19k_hotstart_baud_requires_body9_before_spray(
    src: &str,
) -> Result<(), &'static str> {
    let Some(start) = src.find("fn reset_asic_baud(serial_device: &str)") else {
        return Err("missing serial_mining reset_asic_baud");
    };
    let win = src.get(start..start.saturating_add(1800)).unwrap_or("");
    let Some(open_at) = win.find("SerialChainBackend::open(0, serial_device, stage.baud)")
    else {
        return Err("reset_asic_baud must open each stage baud");
    };
    let after = win.get(open_at..).unwrap_or("");
    let Some(req_at) = after.find("require_bm1366_response_body") else {
        return Err("reset_asic_baud must require_bm1366_response_body after open");
    };
    let spray_at = after
        .find("send_chain_inactive")
        .or_else(|| after.find("Hot-start baud-wake stage"));
    if let Some(s) = spray_at {
        if s < req_at {
            return Err("reset_asic_baud must require body 9 before TX spray");
        }
    }
    if !after.contains("set_response_len(BM1366_UART_RESP_BODY_LEN)") {
        return Err("reset_asic_baud must set BM1366 body 9 after open");
    }
    Ok(())
}

pub fn refuse_s19k_nopic_probe_as_track1_first_read() -> Result<(), &'static str> {
    Err("NoPic observe_candidate is BM1368/BM1370 only; not S19k Track-1 first-read")
}

/// AM2 hybrid baud-wake is Zynq BM1362. Do not borrow require_bm1366.
pub fn admit_s19k_am2_hybrid_reset_is_not_bm1366(hybrid_src: &str) -> Result<(), &'static str> {
    let Some(start) = hybrid_src.find("fn reset_asic_baud(serial_device: &str)") else {
        return Err("missing AM2 hybrid reset_asic_baud");
    };
    let win = hybrid_src.get(start..start.saturating_add(1800)).unwrap_or("");
    if !win.contains("HotStartHostClass::Zynq") {
        return Err("AM2 hybrid reset_asic_baud must use Zynq hot-start class");
    }
    if !win.contains("plan_hot_start_hybrid_wake_ops") {
        return Err("AM2 hybrid reset_asic_baud must use hybrid wake ops");
    }
    if win.contains("require_bm1366_response_body") || win.contains("BM1366_UART_RESP_BODY_LEN") {
        return Err("AM2 hybrid reset_asic_baud must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am2_hybrid_open_as_track1_first_read() -> Result<(), &'static str> {
    Err("AM2 hybrid reset_asic_baud is Zynq BM1362; not S19k Track-1 first-read")
}

/// AM2 reset-baseline first-read is BM1362 unassigned body, not BM1366 body 9.
pub fn admit_s19k_am2_reset_baseline_is_not_bm1366(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn observe_reset_baseline(") else {
        return Err("missing observe_reset_baseline");
    };
    let win = src.get(start..start.saturating_add(1800)).unwrap_or("");
    if !win.contains("BM1362_UNASSIGNED_RESP_BODY_LEN") {
        return Err("AM2 reset-baseline must set BM1362 unassigned body");
    }
    if !win.contains("AM2 BM1362 reset-baseline") {
        return Err("AM2 reset-baseline must name BM1362");
    }
    if win.contains("require_bm1366_response_body") || win.contains("BM1366_UART_RESP_BODY_LEN") {
        return Err("AM2 reset-baseline must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am2_reset_baseline_as_track1_first_read() -> Result<(), &'static str> {
    Err("AM2 observe_reset_baseline is BM1362; not S19k Track-1 first-read")
}

/// am3-bb kernel UART open is BeagleBone, not S19k Track-1.
pub fn admit_s19k_am3_bb_open_is_not_bm1366(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("impl Am3BbChainUart") else {
        return Err("missing Am3BbChainUart");
    };
    let win = src.get(start..start.saturating_add(2500)).unwrap_or("");
    if !win.contains("am3-bb: SerialChainBackend::open") {
        return Err("am3-bb must name SerialChainBackend::open");
    }
    if win.contains("require_bm1366_response_body") || win.contains("open_passthrough_bm1366") {
        return Err("am3-bb open must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am3_bb_open_as_track1_first_read() -> Result<(), &'static str> {
    Err("am3-bb SerialChainBackend::open is BeagleBone; not S19k Track-1 first-read")
}

/// Leftover BM1398 init is not S19k Track-1 first-read.
pub fn admit_s19k_init_bm1398_is_not_bm1366(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1398_chain(") else {
        return Err("missing init_bm1398_chain");
    };
    let win = src.get(start..start.saturating_add(4000)).unwrap_or("");
    if !win.contains("SerialBringUpPluginKind::SerialBm1398") {
        return Err("init_bm1398_chain must use SerialBm1398 bring-up");
    }
    if !win.contains("send_get_address_bm1397plus") {
        return Err("init_bm1398_chain must use BM1397+ GetAddress");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("init_bm1398_chain must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_init_bm1398_as_track1_first_read() -> Result<(), &'static str> {
    Err("init_bm1398_chain is BM1398; not S19k Track-1 first-read")
}

/// Leftover BM1368 init reuses an admitted ValidatedSerialBackend; not S19k Track-1 first-read.
pub fn admit_s19k_init_bm1368_is_not_bm1366(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1368_chain(") else {
        return Err("missing init_bm1368_chain");
    };
    let win = src.get(start..start.saturating_add(4000)).unwrap_or("");
    if !win.contains("ValidatedSerialBackend") {
        return Err("init_bm1368_chain must take ValidatedSerialBackend, not a fresh UART open");
    }
    if !win.contains("SerialBringUpPluginKind::AmlogicBm1368") {
        return Err("init_bm1368_chain must use AmlogicBm1368 bring-up");
    }
    if !win.contains("=== BM1368 ASIC INIT") {
        return Err("init_bm1368_chain must name BM1368 ASIC INIT");
    }
    if win.contains("SerialChainBackend::open") {
        return Err("init_bm1368_chain must not open a new SerialChainBackend");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("init_bm1368_chain must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_init_bm1368_as_track1_first_read() -> Result<(), &'static str> {
    Err("init_bm1368_chain is BM1368 ValidatedSerialBackend; not S19k Track-1 first-read")
}

/// Leftover BM1370 init reuses an admitted ValidatedSerialBackend; not S19k Track-1 first-read.
pub fn admit_s19k_init_bm1370_is_not_bm1366(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1370_chain(") else {
        return Err("missing init_bm1370_chain");
    };
    let win = src.get(start..start.saturating_add(4000)).unwrap_or("");
    if !win.contains("ValidatedSerialBackend") {
        return Err("init_bm1370_chain must take ValidatedSerialBackend, not a fresh UART open");
    }
    if !win.contains("SerialBringUpPluginKind::AmlogicBm1370") {
        return Err("init_bm1370_chain must use AmlogicBm1370 bring-up");
    }
    if !win.contains("=== BM1370 ASIC INIT") {
        return Err("init_bm1370_chain must name BM1370 ASIC INIT");
    }
    if !win.contains("send_get_address_bm1397plus") {
        return Err("init_bm1370_chain must use BM1397+ GetAddress");
    }
    if win.contains("SerialChainBackend::open") {
        return Err("init_bm1370_chain must not open a new SerialChainBackend");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("init_bm1370_chain must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_init_bm1370_as_track1_first_read() -> Result<(), &'static str> {
    Err("init_bm1370_chain is BM1370 ValidatedSerialBackend; not S19k Track-1 first-read")
}

/// Leftover BM1362 init reuses an admitted ValidatedSerialBackend; not S19k Track-1 first-read.
pub fn admit_s19k_init_bm1362_is_not_bm1366(src: &str) -> Result<(), &'static str> {
    let Some(start) = src.find("fn init_bm1362_chain(") else {
        return Err("missing init_bm1362_chain");
    };
    let win = src.get(start..start.saturating_add(2500)).unwrap_or("");
    if !win.contains("ValidatedSerialBackend") {
        return Err("init_bm1362_chain must take ValidatedSerialBackend, not a fresh UART open");
    }
    if !win.contains("=== BM1362 ASIC INIT") {
        return Err("init_bm1362_chain must name BM1362 ASIC INIT");
    }
    if !win.contains("BM1362 init requires the checked reset-baseline 115200") {
        return Err("init_bm1362_chain must require the 115200 reset-baseline route");
    }
    if win.contains("SerialChainBackend::open") {
        return Err("init_bm1362_chain must not open a new SerialChainBackend");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("init_bm1362_chain must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_init_bm1362_as_track1_first_read() -> Result<(), &'static str> {
    Err("init_bm1362_chain is BM1362 ValidatedSerialBackend; not S19k Track-1 first-read")
}

/// AM2 RANK-5 companion PL-UART is Zynq BM1362 dual-UART, not S19k Track-1.
pub fn admit_s19k_am2_companion_open_is_not_bm1366(hybrid_src: &str) -> Result<(), &'static str> {
    let Some(start) = hybrid_src.find("let companion_dev = am2_dual_chain_second_uart()")
    else {
        return Err("missing AM2 companion UART open");
    };
    let win = hybrid_src.get(start..start.saturating_add(2500)).unwrap_or("");
    if !win.contains("SerialChainBackend::open(0, &companion_dev, 115_200)") {
        return Err("AM2 companion must open companion_dev at 115200");
    }
    if !win.contains("assert_mcr_out2") {
        return Err("AM2 companion must assert OUT2");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("AM2 companion must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am2_companion_open_as_track1_first_read() -> Result<(), &'static str> {
    Err("AM2 companion UART open is Zynq BM1362; not S19k Track-1 first-read")
}

/// AM2 Phase 3b1-relay is BM1362 UART relay lab stage, not S19k Track-1.
pub fn admit_s19k_am2_phase3b1_relay_is_not_bm1366(hybrid_src: &str) -> Result<(), &'static str> {
    let Some(start) = hybrid_src.find("dcentrald_hal::serial_chain::SerialChainBackend::open(")
    else {
        return Err("missing Phase 3b1-relay SerialChainBackend::open");
    };
    let win = hybrid_src.get(start..start.saturating_add(1800)).unwrap_or("");
    if !win.contains("maybe_write_bm1362_uart_relay") {
        return Err("Phase 3b1-relay must write BM1362 UART relay");
    }
    if !win.contains("bm1362_phase3b1_pre_gate") {
        return Err("Phase 3b1-relay must name bm1362_phase3b1_pre_gate");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("Phase 3b1-relay must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am2_phase3b1_relay_as_track1_first_read() -> Result<(), &'static str> {
    Err("AM2 Phase 3b1-relay is BM1362 UART relay; not S19k Track-1 first-read")
}

/// AM2 PL UART probe is BM1362 fallback sweep, not S19k Track-1 first-read.
pub fn admit_s19k_am2_probe_uart_is_not_bm1366(hybrid_src: &str) -> Result<(), &'static str> {
    let Some(start) = hybrid_src.find("fn probe_uart_for_chips(") else {
        return Err("missing probe_uart_for_chips");
    };
    let win = hybrid_src.get(start..start.saturating_add(2500)).unwrap_or("");
    if !win.contains("BM1362_RESP_BODY_LEN") {
        return Err("AM2 UART probe must set BM1362 response body");
    }
    if !win.contains("hybrid_send_get_address") {
        return Err("AM2 UART probe must use hybrid GetAddress");
    }
    if !win.contains("read_bm1362_serial_drain_summary") {
        return Err("AM2 UART probe must drain BM1362 summary");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("AM2 UART probe must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am2_probe_uart_as_track1_first_read() -> Result<(), &'static str> {
    Err("AM2 probe_uart_for_chips is Zynq BM1362; not S19k Track-1 first-read")
}

/// AM2 hybrid init_asic_chain primary 115200 open is BM1362, not S19k Track-1.
pub fn admit_s19k_am2_init_asic_open_is_not_bm1366(hybrid_src: &str) -> Result<(), &'static str> {
    let Some(fn_at) = hybrid_src.find("fn init_asic_chain(") else {
        return Err("missing AM2 init_asic_chain");
    };
    let head = hybrid_src.get(fn_at..fn_at.saturating_add(800)).unwrap_or("");
    if !head.contains("=== BM1362 ASIC INIT") {
        return Err("AM2 init_asic_chain must name BM1362 ASIC INIT");
    }
    let rest = hybrid_src.get(fn_at..).unwrap_or("");
    let Some(open_at) = rest.find("let mut serial = SerialChainBackend::open(0, serial_device, 115_200)")
    else {
        return Err("AM2 init_asic_chain must open primary UART at 115200");
    };
    let win = rest.get(open_at..open_at.saturating_add(1500)).unwrap_or("");
    if !win.contains("am2_post_reset_settle_ms") {
        return Err("AM2 init_asic_chain primary open must settle via am2_post_reset_settle_ms");
    }
    if !win.contains("Failed to open serial port at 115200") {
        return Err("AM2 init_asic_chain primary open must name 115200 failure");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("AM2 init_asic_chain must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am2_init_asic_open_as_track1_first_read() -> Result<(), &'static str> {
    Err("AM2 init_asic_chain primary open is Zynq BM1362; not S19k Track-1 first-read")
}

/// AM2 hybrid mining-on passthrough is BM1362 DEFAULT-7 open, not S19k Track-1.
pub fn admit_s19k_am2_passthrough0_is_not_bm1366(hybrid_src: &str) -> Result<(), &'static str> {
    let Some(start) = hybrid_src.find("PASSTHROUGH: skipping Phase 1-7 (bosminer owns PIC+chain init)")
    else {
        return Err("missing AM2 hybrid passthrough skip");
    };
    let win = hybrid_src.get(start..start.saturating_add(800)).unwrap_or("");
    if !win.contains("open_passthrough(0, &serial_device)") {
        return Err("AM2 hybrid passthrough must open_passthrough(0)");
    }
    if !win.contains("BM1362_RESP_BODY_LEN") {
        return Err("AM2 hybrid passthrough must set BM1362 response body");
    }
    if win.contains("require_bm1366_response_body")
        || win.contains("open_passthrough_bm1366")
        || win.contains("BM1366_UART_RESP_BODY_LEN")
    {
        return Err("AM2 hybrid passthrough must not borrow BM1366 first-read");
    }
    Ok(())
}

pub fn refuse_s19k_am2_passthrough0_as_track1_first_read() -> Result<(), &'static str> {
    Err("AM2 hybrid open_passthrough(0) is Zynq BM1362; not S19k Track-1 first-read")
}

pub fn admit_s19k_production_uses_tagged_fill_hunt(src: &str) -> Result<(), &'static str> {
    if !src.contains("hunt_s19k_bm1366_fill_from_tagged_slot") {
        return Err("production hunter must call hunt_s19k_bm1366_fill_from_tagged_slot");
    }
    if !src.contains("S19kOutstandingFillTx") {
        return Err("production must index outstanding fill TX by job-id slot");
    }
    if src.contains("outstanding_s19k_tx.len() >= 32") {
        return Err("production must not FIFO-wrap outstanding fill TX");
    }
    refuse_tautological_fill_qualify_source(src)?;
    refuse_esp_bip320_as_braiins_fill_version(src)?;
    refuse_esp_midstate_as_braiins_fill_index(src)?;
    refuse_esp_flags_redrop_after_fill_hunt(src)?;
    if !src.contains("0u16, // fill log 0") {
        return Err("production fill arm must pass version_bits_raw = 0 (fill log 0)");
    }
    if !src.contains("0u8, // fill midstates=1") {
        return Err("production fill arm must pass midstate_idx = 0 (fill midstates=1)");
    }
    if !src.contains("0x80, // fill hunt") {
        return Err("production fill arm must not re-drop on ESP resp[8] after hunt");
    }
    Ok(())
}

/// Classify + qualify one 11-byte UART frame.
pub fn share_from_uart_frame(
    frame: &[u8],
    expected_job_id: u8,
    base_version: u32,
) -> Result<S19kBm1366Share, S19kShareError> {
    let kind = classify_bm1366_uart_rx(frame).map_err(|_| S19kShareError::NotJobNonce)?;
    qualify_bm1366_job_nonce(kind, expected_job_id, base_version)
}

pub fn refuse_bm1368_job_id_extract(id: u8) -> u8 {
    // Document the wrong extract so tests can refuse it.
    (id & 0xF0) >> 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s21_comparative_nonce_reconstructs_share_without_crc_drop() {
        // Comparative BM1368 live frame decoded with **BM1366** masks.
        let frame = [
            0xAA, 0x55, 0x60, 0x96, 0x39, 0x4C, 0x02, 0x14, 0x03, 0x04, 0x8E,
        ];
        let base = 0x2000_0000u32;
        let share = share_from_uart_frame(&frame, 0x10, base).unwrap();
        assert_eq!(share.job_id, 0x10);
        assert_eq!(share.small_core, 0x04);
        assert_eq!(share.midstate_num, 0x02);
        assert_eq!(share.nonce_be, 0x6096_394C);
        assert_eq!(share.nonce_le, 0x4C39_9660);
        assert_eq!(BM1366_VERSION_ROLL_MASK, 0x1FFF_E000);
        assert_ne!(BM1366_VERSION_ROLL_MASK, 0x1FFE_0000);
        // 0x0304 << 13 = 0x0060_8000; bits 13..16 must survive the mask.
        assert_eq!(0x0304u32 << 13, 0x0060_8000);
        assert_eq!(share.version_bits, 0x0304u32 << 13);
        assert_eq!(share.version_bits & 0x0000_8000, 0x0000_8000);
        assert_eq!(share.rolled_version, reconstruct_rolled_version(base, 0x0304));
        assert_eq!(
            reconstruct_rolled_version(0x2000_0000, 0x0304),
            0x2000_0000 | 0x0060_8000
        );
        assert_eq!(share.asic_index, share.chip_addr / crate::s19k_bm1366_wire_b::S19K_AML_ADDR_INTERVAL);
        assert_eq!(crate::s19k_bm1366_wire_b::S19K_AML_ADDR_INTERVAL, 2);
        // Wrong family extract must not be used.
        assert_ne!(refuse_bm1368_job_id_extract(0x14), share.job_id);
        // BM1368 `(id & 0xF0) >> 1`: 0x14 → 0x08. Not BM1366 `id & 0xF8` → 0x10.
        assert_eq!(refuse_bm1368_job_id_extract(0x14), 0x08);
        // ChipAddress must not qualify as a share.
        let chip = [
            0xAA, 0x55, 0x13, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(matches!(
            share_from_uart_frame(&chip, 0x10, base),
            Err(S19kShareError::NotJobNonce)
        ));
        assert!(share_from_uart_frame(&frame, 0x08, base).is_err());
        let body = &frame[2..];
        let from_body = parse_bm1366_share_from_body(body, base).unwrap();
        assert_eq!(from_body.job_id, share.job_id);
        assert_eq!(from_body.nonce_le, share.nonce_le);
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(
            serial.contains("hunt_s19k_bm1366_fill_from_tagged_slot"),
            "production BM1366 nonce path must hunt tagged fill against the job-id slot"
        );
        assert!(serial.contains("else if is_bm1366"));
        assert!(admit_s19k_share_job_id_in_history(true, 0x10).is_ok());
        assert!(admit_s19k_share_job_id_in_history(false, 0x10).is_err());
        assert!(
            !serial.contains("admit_s19k_share_job_id_in_history"),
            "S19k BM1366 must not use ESP 0xF8 history admit"
        );
        assert!(
            serial.contains("hunt_s19k_bm1366_fill_from_tagged_slot"),
            "Braiins fill RX must hunt the job-id slot, not a 32-deep FIFO"
        );
        assert!(
            admit_s19k_production_uses_tagged_fill_hunt(serial).is_ok(),
            "Braiins fill RX must hunt tagged body against outstanding 21 36 TX"
        );
        assert!(admit_s19k_production_hunt_uses_body9(serial).is_ok());
        assert!(admit_s19k_production_hunt_uses_body9(
            "hunt_s19k_bm1366_fill_from_tagged_slot\nSome(&resp[..7])\nBM1366_UART_RESP_BODY_LEN"
        )
        .is_err());
        assert!(refuse_s19k_production_bm1366_hunt_as_hal_body7().is_err());
        assert!(admit_s19k_production_sets_body_before_first_read(serial).is_ok());
        assert!(admit_s19k_production_sets_body_before_first_read(
            "SerialChainBackend::open_passthrough_bm1366(i as u8, path)\nsend_get_address\ns.set_response_len(resp_body_len)"
        )
        .is_err());
        assert!(refuse_hal_default_body7_as_bm1366_first_read(7).is_err());
        assert!(refuse_hal_default_body7_as_bm1366_first_read(9).is_ok());
        assert!(refuse_s19k_skip_bm1366_open_first_read_at_7(false, 7).is_err());
        assert!(refuse_s19k_skip_bm1366_open_first_read_at_7(true, 7).is_ok());
        assert!(refuse_s19k_skip_bm1366_open_first_read_at_7(false, 9).is_ok());
        assert!(admit_s19k_production_requires_body9_before_first_read(serial).is_ok());
        assert!(admit_s19k_production_requires_body9_before_first_read(
            "SerialChainBackend::open_passthrough_bm1366(i as u8, path)\nsend_get_address\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(admit_s19k_init_bm1366_requires_body9_before_flush(serial).is_ok());
        assert!(admit_s19k_init_bm1366_requires_body9_before_flush(
            "fn init_bm1366_chain(\nSerialChainBackend::open(0, serial_device, 115_200)\nflush_io\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(admit_s19k_init_bm1366_omits_esp_a4(serial).is_ok());
        assert!(admit_s19k_init_bm1366_omits_esp_a4(
            "fn init_bm1366_chain(\nBM1366_VERSION_MASK_VALUE\nfn init_bm1370_chain("
        )
        .is_err());
        assert!(admit_s19k_production_run_skips_init_bm1366_chain(serial).is_ok());
        assert!(admit_s19k_nopic_observation_refuses_bm1366(serial).is_ok());
        assert!(admit_s19k_nopic_observation_refuses_bm1366(
            "fn begin_nopic_observation(\nAsicProtocolIdentity::Bm1366\n"
        )
        .is_err());
        assert!(admit_s19k_hotstart_baud_requires_body9_before_spray(serial).is_ok());
        assert!(admit_s19k_hotstart_baud_requires_body9_before_spray(
            "fn reset_asic_baud(serial_device: &str)\nSerialChainBackend::open(0, serial_device, stage.baud)\nsend_chain_inactive"
        )
        .is_err());
        assert!(refuse_s19k_nopic_probe_as_track1_first_read().is_err());
        const HYBRID: &str = include_str!("../../dcentrald/src/s19j_hybrid_mining.rs");
        assert!(admit_s19k_am2_hybrid_reset_is_not_bm1366(HYBRID).is_ok());
        assert!(admit_s19k_am2_hybrid_reset_is_not_bm1366(
            "fn reset_asic_baud(serial_device: &str)\nHotStartHostClass::Zynq\nplan_hot_start_hybrid_wake_ops\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_am2_hybrid_open_as_track1_first_read().is_err());
        assert!(admit_s19k_am2_reset_baseline_is_not_bm1366(serial).is_ok());
        assert!(admit_s19k_am2_reset_baseline_is_not_bm1366(
            "fn observe_reset_baseline(\nBM1362_UNASSIGNED_RESP_BODY_LEN\nAM2 BM1362 reset-baseline\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_am2_reset_baseline_as_track1_first_read().is_err());
        const AM3_BB: &str = include_str!("../../dcentrald/src/am3_bb_mining.rs");
        assert!(admit_s19k_am3_bb_open_is_not_bm1366(AM3_BB).is_ok());
        assert!(admit_s19k_am3_bb_open_is_not_bm1366(
            "impl Am3BbChainUart\nam3-bb: SerialChainBackend::open\nopen_passthrough_bm1366"
        )
        .is_err());
        assert!(refuse_s19k_am3_bb_open_as_track1_first_read().is_err());
        assert!(admit_s19k_init_bm1398_is_not_bm1366(serial).is_ok());
        assert!(admit_s19k_init_bm1398_is_not_bm1366(
            "fn init_bm1398_chain(\nSerialBringUpPluginKind::SerialBm1398\nsend_get_address_bm1397plus\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_init_bm1398_as_track1_first_read().is_err());
        assert!(admit_s19k_init_bm1368_is_not_bm1366(serial).is_ok());
        assert!(admit_s19k_init_bm1368_is_not_bm1366(
            "fn init_bm1368_chain(\nValidatedSerialBackend\nSerialBringUpPluginKind::AmlogicBm1368\n=== BM1368 ASIC INIT\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_init_bm1368_as_track1_first_read().is_err());
        assert!(admit_s19k_init_bm1370_is_not_bm1366(serial).is_ok());
        assert!(admit_s19k_init_bm1370_is_not_bm1366(
            "fn init_bm1370_chain(\nValidatedSerialBackend\nSerialBringUpPluginKind::AmlogicBm1370\n=== BM1370 ASIC INIT\nsend_get_address_bm1397plus\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_init_bm1370_as_track1_first_read().is_err());
        assert!(admit_s19k_init_bm1362_is_not_bm1366(serial).is_ok());
        assert!(admit_s19k_init_bm1362_is_not_bm1366(
            "fn init_bm1362_chain(\nValidatedSerialBackend\n=== BM1362 ASIC INIT\nBM1362 init requires the checked reset-baseline 115200\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_init_bm1362_as_track1_first_read().is_err());
        assert!(admit_s19k_am2_companion_open_is_not_bm1366(HYBRID).is_ok());
        assert!(admit_s19k_am2_companion_open_is_not_bm1366(
            "let companion_dev = am2_dual_chain_second_uart()\nSerialChainBackend::open(0, &companion_dev, 115_200)\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_am2_companion_open_as_track1_first_read().is_err());
        assert!(admit_s19k_am2_phase3b1_relay_is_not_bm1366(HYBRID).is_ok());
        assert!(admit_s19k_am2_phase3b1_relay_is_not_bm1366(
            "dcentrald_hal::serial_chain::SerialChainBackend::open(\nmaybe_write_bm1362_uart_relay\nbm1362_phase3b1_pre_gate\nopen_passthrough_bm1366"
        )
        .is_err());
        assert!(refuse_s19k_am2_phase3b1_relay_as_track1_first_read().is_err());
        assert!(admit_s19k_am2_probe_uart_is_not_bm1366(HYBRID).is_ok());
        assert!(admit_s19k_am2_probe_uart_is_not_bm1366(
            "fn probe_uart_for_chips(\nBM1362_RESP_BODY_LEN\nhybrid_send_get_address\nread_bm1362_serial_drain_summary\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_am2_probe_uart_as_track1_first_read().is_err());
        assert!(admit_s19k_am2_init_asic_open_is_not_bm1366(HYBRID).is_ok());
        assert!(admit_s19k_am2_init_asic_open_is_not_bm1366(
            "fn init_asic_chain(\n=== BM1362 ASIC INIT\nlet mut serial = SerialChainBackend::open(0, serial_device, 115_200)\nFailed to open serial port at 115200\nam2_post_reset_settle_ms\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_am2_init_asic_open_as_track1_first_read().is_err());
        assert!(admit_s19k_am2_passthrough0_is_not_bm1366(HYBRID).is_ok());
        assert!(admit_s19k_am2_passthrough0_is_not_bm1366(
            "PASSTHROUGH: skipping Phase 1-7 (bosminer owns PIC+chain init)\nopen_passthrough(0, &serial_device)\nBM1362_RESP_BODY_LEN\nrequire_bm1366_response_body"
        )
        .is_err());
        assert!(refuse_s19k_am2_passthrough0_as_track1_first_read().is_err());
        const HAL: &str = include_str!("../../dcentrald-hal/src/serial_chain.rs");
        assert!(admit_s19k_hal_open_passthrough_bm1366(HAL).is_ok());
        assert!(crate::s19k_bm1366_uart_rx::admit_s19k_hal_extracts_bm1366_body9(HAL).is_ok());
        assert!(crate::s19k_bm1366_uart_rx::admit_s19k_hal_midstream_body7_then_body9(HAL).is_ok());
        assert!(admit_s19k_production_uses_bm1366_passthrough_open(serial).is_ok());
        assert!(admit_s19k_production_uses_bm1366_passthrough_open(
            "SerialChainBackend::open_passthrough(i as u8, path)"
        )
        .is_err());
        assert!(admit_s19k_production_refuses_generic_passthrough_for_bm1366(serial).is_ok());
        assert!(admit_s19k_production_refuses_generic_passthrough_for_bm1366(
            "} else if passthrough {\n            let mut s = SerialChainBackend::open_passthrough(0, &serial_device)"
        )
        .is_err());
        assert!(refuse_s19k_generic_passthrough0_as_track1().is_err());
        assert!(refuse_tautological_fill_qualify_source(
            "qualify_bm1366_braiins_fill_from_body(&resp[..9], share.job_id, 0)"
        )
        .is_err());
        assert!(
            serial.contains("format_s19k_port_rx_matrix"),
            "passthrough GetAddress must log per-port RX, not a single ChipAnswered"
        );
        assert!(
            serial.contains("refuse_one_required_port_as_dual_chain_proof"),
            "one answering UART must not be dual-chain proof"
        );
        assert!(
            serial.contains("refuse_zero_required_ports_as_dual_chain_proof"),
            "zero required UART answers must not be dual-chain proof"
        );
        assert!(
            serial.contains("refuse_s3_only_as_required_pair_proof"),
            "ttyS3-only ChipAddress must not be required-pair proof"
        );
        assert!(
            serial.contains("admit_s19k_braiins_fill_share_job_id_in_history"),
            "Braiins fill history must not mask 0xF8"
        );
        let fill_frame = [
            0xAA, 0x55, 0x11, 0x22, 0x33, 0x44, 0x00, 0x02, 0x00, 0x00, 0x80,
        ];
        let fill = parse_bm1366_braiins_fill_share_from_body(&fill_frame[2..], base).unwrap();
        assert_eq!(fill.job_id, 2);
        assert_ne!(fill.job_id, 2u8 << 3);
        assert_eq!(fill.nonce_be, 0x1122_3344);
        assert_eq!(
            fill.nonce_be,
            crate::s19k_braiins_job::s19k_braiins_fill_nonce_word(0x1122_3344)
        );
        assert_eq!(fill.nonce_le, 0x4433_2211);
        assert_eq!(
            crate::s19k_braiins_job::s19k_braiins_uart_version_bits(0xABCD, 0).unwrap(),
            0
        );
        assert_eq!(fill.version_bits, 0);
        assert_eq!(fill.rolled_version, base);
        assert_eq!(fill.midstate_num, 0);
        let noisy = [0x11, 0x22, 0x33, 0x44, 0x07, 0x02, 0xAB, 0xCD, 0x80];
        let noisy_fill = parse_bm1366_braiins_fill_share_from_body(&noisy, base).unwrap();
        assert_eq!(noisy_fill.version_bits, 0);
        assert_eq!(noisy_fill.rolled_version, base);
        assert_eq!(noisy_fill.job_id, 2);
        assert_eq!(noisy_fill.midstate_num, 0);
        let esp_noisy = parse_bm1366_share_from_body(&noisy, base).unwrap();
        assert_ne!(esp_noisy.version_bits, 0);
        assert_eq!(esp_noisy.midstate_num, 0x07);
        assert!(refuse_esp_midstate_as_braiins_fill_index("share.midstate_num").is_err());
        assert!(refuse_esp_midstate_as_braiins_fill_index("0u8, // fill midstates=1").is_ok());
        assert!(refuse_esp_flags_redrop_after_fill_hunt(
            "0u16, // fill log 0\nresp[8],"
        )
        .is_err());
        assert!(refuse_esp_flags_redrop_after_fill_hunt(
            "0u16, // fill log 0\n0x80, // fill hunt"
        )
        .is_ok());
        assert!(refuse_esp_bip320_as_braiins_fill_version(
            "(share.version_bits >> 13) as u16"
        )
        .is_err());
        assert!(refuse_esp_bip320_as_braiins_fill_version("0u16, // fill log 0").is_ok());
        let esp = parse_bm1366_share_from_body(&fill_frame[2..], base).unwrap();
        assert_eq!(esp.job_id, 0);
        assert!(refuse_esp_f8_mask_as_braiins_fill_job_id(0x02).is_err());
        assert!(refuse_esp_step8_as_braiins_fill_registry(8, 0x7F).is_err());
        assert!(refuse_esp_step8_as_braiins_fill_registry(1, 0xFF).is_ok());
        assert!(admit_s19k_braiins_fill_share_job_id_in_history(true, 2).is_ok());
        assert!(admit_s19k_braiins_fill_share_job_id_in_history(false, 2).is_err());
        assert!(refuse_esp_qualify_as_braiins_fill(2).is_err());
        assert!(refuse_esp_qualify_as_braiins_fill(0x10).is_ok());
        let q = qualify_bm1366_braiins_fill_from_body(&SYNTHETIC_BM1366_FILL_WORK2_BODY, 2, base)
            .unwrap();
        assert_eq!(q.job_id, 2);
        assert!(qualify_bm1366_braiins_fill_from_body(&SYNTHETIC_BM1366_FILL_WORK2_BODY, 0x10, base)
            .is_err());
        let tx2 = s19k_fill_tx_prefix(2).to_vec();
        let tx3 = s19k_fill_tx_prefix(3).to_vec();
        let hit = hunt_s19k_bm1366_fill_from_tagged_outstanding(
            "/dev/ttyS1",
            Some(&SYNTHETIC_BM1366_FILL_WORK2_BODY),
            &[tx2.clone()],
        )
        .unwrap();
        assert_eq!(hit.job_id, 2);
        assert!(hunt_s19k_bm1366_fill_from_tagged_outstanding(
            "/dev/ttyS1",
            Some(&SYNTHETIC_BM1366_FILL_WORK2_BODY),
            &[tx3],
        )
        .is_err());
        assert!(hunt_s19k_bm1366_fill_from_tagged_outstanding(
            "/dev/ttyS1",
            Some(&SYNTHETIC_BM1366_FILL_WORK2_BODY),
            &[],
        )
        .is_err());
        assert!(hunt_s19k_bm1366_fill_from_tagged_outstanding(
            "/dev/ttyS0",
            Some(&SYNTHETIC_BM1366_FILL_WORK2_BODY),
            &[tx2.clone()],
        )
        .is_err());
        assert!(hunt_s19k_bm1366_fill_from_tagged_outstanding(
            "/dev/ttyS1",
            None,
            &[tx2.clone()],
        )
        .is_err());
        let cut7 = &SYNTHETIC_BM1366_FILL_WORK2_BODY[..7];
        let cut7_err = hunt_s19k_bm1366_fill_from_tagged_outstanding(
            "/dev/ttyS2",
            Some(cut7),
            &[tx2.clone()],
        )
        .expect_err("HAL body-7 must not hunt as a share");
        assert!(
            cut7_err.contains("framing") || cut7_err.contains("not JobNonce"),
            "HAL body-7 must be framing, not silence: {cut7_err}"
        );
        assert!(!cut7_err.contains("silence"));
        assert!(refuse_constructed_fill_hal_body7_wire_as_share(
            "/dev/ttyS1",
            2,
            &[tx2.clone()],
        )
        .is_err());
        assert!(refuse_constructed_fill_hal_body7_wire_as_share("/dev/ttyS0", 2, &[tx2.clone()]).is_ok());
        let taut = qualify_bm1366_braiins_fill_from_body(
            &SYNTHETIC_BM1366_FILL_WORK2_BODY,
            parse_bm1366_braiins_fill_share_from_body(&SYNTHETIC_BM1366_FILL_WORK2_BODY, base)
                .unwrap()
                .job_id,
            base,
        );
        assert!(taut.is_ok(), "self-qualify is tautological; hunt requires TX");
        assert_eq!(S19K_FILL_TX_SLOTS, 256);
        assert!(refuse_s19k_fifo32_wrap_as_outstanding_table().is_err());
        assert!(admit_s19k_uart_queue_covers_fill_slots(S19K_FILL_TX_SLOTS).is_ok());
        assert!(admit_s19k_uart_queue_covers_fill_slots(16).is_err());
        assert!(refuse_s19k_uart_queue16_as_fill_depth(16).is_err());
        assert!(refuse_s19k_uart_queue16_as_fill_depth(256).is_ok());
        assert!(admit_s19k_production_bm1366_queue_covers_fill_slots(serial).is_ok());
        assert!(admit_s19k_production_bm1366_queue_covers_fill_slots(
            "let work_queue_depth = if is_bm1362 {\nBM1362_SERIAL_WORK_QUEUE_DEPTH\n} else {\nDEFAULT_SERIAL_WORK_QUEUE_DEPTH\n}"
        )
        .is_err());
        assert!(admit_s19k_track1_thermal_handoff_unowned(serial).is_ok());
        assert!(admit_s19k_track1_thermal_handoff_unowned(
            "let thermal_proof_present = am2_fan.is_some() || braiins_bm1366_passthrough_handoff;"
        )
        .is_err());
        assert!(refuse_s19k_track1_handoff_as_thermal_ready().is_err());
        assert!(admit_s19k_production_bm1366_tx_before_rx(serial).is_ok());
        assert!(admit_s19k_production_bm1366_tx_before_rx("let tx_before_rx = is_bm1362;").is_err());
        assert!(admit_s19k_init_bm1366_requires_experimental_env(serial).is_ok());
        assert!(admit_s19k_init_bm1366_requires_experimental_env(
            "fn init_bm1366_chain(\nSelf::reset_asic_baud"
        )
        .is_err());
        assert_eq!(
            crate::work_dispatch_safety::admit_work_dispatch(
                &crate::work_dispatch_safety::WorkDispatchSafetyInputs {
                    watchdog: crate::work_dispatch_safety::WatchdogSafetyState::Armed,
                    heartbeat_requirement:
                        crate::work_dispatch_safety::HeartbeatRequirement::NoneRequired,
                    controllers: vec![],
                    thermal: crate::work_dispatch_safety::ThermalSafetyState::HandoffUnowned,
                    previously_revoked: false,
                }
            )
            .unwrap()
            .thermal,
            crate::work_dispatch_safety::ThermalSafetyState::HandoffUnowned
        );
        assert!(s19k_fill_job_id_from_tx_wire(&tx2).unwrap() == 2);
        assert!(s19k_fill_job_id_from_tx_wire(&[0x55, 0xAA, 0x21, 0x56, 2]).is_err());
        let body0 = [0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x80];
        let mut slots = S19kOutstandingFillTx::new();
        let mut fifo: Vec<Vec<u8>> = Vec::new();
        for id in 0u8..=40 {
            let tx = s19k_fill_tx_prefix(id).to_vec();
            assert_eq!(slots.insert_wire(tx.clone()).unwrap(), id);
            fifo.push(tx);
            if fifo.len() > 32 {
                fifo.remove(0);
            }
        }
        assert_eq!(slots.occupied(), 41);
        assert!(slots.get(0).is_some());
        assert!(fifo.iter().all(|tx| tx.get(4) != Some(&0)));
        assert!(hunt_s19k_bm1366_fill_from_tagged_outstanding(
            "/dev/ttyS1",
            Some(&body0),
            &fifo,
        )
        .is_err());
        let slot_hit = hunt_s19k_bm1366_fill_from_tagged_slot(
            "/dev/ttyS1",
            Some(&body0),
            &slots,
        )
        .unwrap();
        assert_eq!(slot_hit.job_id, 0);
        let slot2 = hunt_s19k_bm1366_fill_from_tagged_slot(
            "/dev/ttyS1",
            Some(&SYNTHETIC_BM1366_FILL_WORK2_BODY),
            &slots,
        )
        .unwrap();
        assert_eq!(slot2.job_id, 2);
        assert_eq!(
            s19k_fill_job_byte_or_small_core(
                S19K_CONSTRUCTED_FILL_JOB_ID,
                S19K_CONSTRUCTED_FILL_SMALL_CORE
            ),
            S19K_CONSTRUCTED_FILL_JOB_OR_CORE
        );
        let mut overlay_slots = S19kOutstandingFillTx::new();
        overlay_slots
            .insert_wire(s19k_fill_tx_prefix(S19K_CONSTRUCTED_FILL_JOB_ID).to_vec())
            .unwrap();
        assert!(hunt_s19k_bm1366_fill_from_tagged_slot(
            "/dev/ttyS1",
            Some(&S19K_CONSTRUCTED_FILL_WORK10_CORE2_BODY),
            &overlay_slots,
        )
        .is_err());
        let esp_overlay = s19k_fill_lookup_tx_esp_overlay_experimental(
            S19K_CONSTRUCTED_FILL_JOB_OR_CORE,
            &overlay_slots,
        )
        .unwrap();
        assert_eq!(esp_overlay.1, S19K_CONSTRUCTED_FILL_JOB_ID);
        overlay_slots
            .insert_wire(s19k_fill_tx_prefix(S19K_CONSTRUCTED_FILL_JOB_OR_CORE).to_vec())
            .unwrap();
        let identity_wins = hunt_s19k_bm1366_fill_from_tagged_slot(
            "/dev/ttyS1",
            Some(&S19K_CONSTRUCTED_FILL_WORK10_CORE2_BODY),
            &overlay_slots,
        )
        .unwrap();
        assert_eq!(identity_wins.job_id, S19K_CONSTRUCTED_FILL_JOB_OR_CORE);
        assert!(admit_s19k_fill_lookup_uses_raw_job_byte(
            S19K_CONSTRUCTED_FILL_JOB_OR_CORE,
            identity_wins.job_id
        )
        .is_ok());
        assert!(refuse_constructed_fill_hal_body7_extract_as_share(
            "/dev/ttyS1",
            2,
            &slots,
        )
        .is_err());
        assert!(refuse_constructed_fill_hal_body7_extract_as_share(
            "/dev/ttyS0",
            2,
            &slots,
        )
        .is_ok());
        let extracted = admit_constructed_fill_hal_body9_extract_hunts("/dev/ttyS1", 2, &slots)
            .unwrap();
        assert_eq!(extracted.job_id, 2);
        assert!(refuse_s19k_body7_two_frame_extract_as_shares("/dev/ttyS1", &slots).is_err());
        assert!(refuse_s19k_body7_two_frame_extract_as_shares("/dev/ttyS0", &slots).is_ok());
        let recovered = admit_s19k_body7_then_body9_next_frame_hunts("/dev/ttyS1", 2, 3, &slots)
            .unwrap();
        assert_eq!(recovered.job_id, 3);
        assert!(admit_s19k_body7_then_body9_next_frame_hunts("/dev/ttyS0", 2, 3, &slots).is_err());
        slots.clear();
        assert!(hunt_s19k_bm1366_fill_from_tagged_slot(
            "/dev/ttyS1",
            Some(&body0),
            &slots,
        )
        .is_err());
        overlay_slots
            .insert_wire(s19k_fill_tx_prefix(S19K_CONSTRUCTED_FILL_JOB_ID).to_vec())
            .ok();
        assert!(hunt_s19k_bm1366_fill_from_tagged_slot(
            "/dev/ttyS3",
            Some(&S19K_CONSTRUCTED_FILL_WORK10_CORE2_BODY),
            &overlay_slots,
        )
        .is_err());
        assert!(admit_s19k_production_uses_tagged_fill_hunt(serial).is_ok());
        let header = admit_s19k_constructed_fill_hunts_and_headers().unwrap();
        assert_eq!(header.len(), 80);
        assert_eq!(
            &header[0..4],
            &S19K_CONSTRUCTED_FILL_BASE_VERSION.to_le_bytes()
        );
        assert_eq!(&header[4..36], &S19K_CONSTRUCTED_FILL_PREV);
        assert_eq!(&header[36..68], &S19K_CONSTRUCTED_FILL_MERKLE);
        assert!(refuse_constructed_fill_header_as_bip320_strip(&header).is_ok());
        let mut stripped = header;
        stripped[0..4].copy_from_slice(
            &crate::s19k_braiins_job::refuse_bip320_strip_as_braiins_fill_ver0(
                S19K_CONSTRUCTED_FILL_BASE_VERSION,
                0,
            )
            .to_le_bytes(),
        );
        assert!(refuse_constructed_fill_header_as_bip320_strip(&stripped).is_err());
        let endian = admit_s19k_fill_header_uses_workentry_prev_not_wire().unwrap();
        assert_eq!(
            &endian[4..36],
            &s19k_workentry_prev_from_stratum(&S19K_STRATUM_PREV_ASYM)
        );
        assert_ne!(&endian[4..36], &S19K_STRATUM_PREV_ASYM);
        assert!(refuse_s19k_stratum_prev_as_fill_header().is_err());
        assert!(refuse_s19k_wire_word_reverse_as_fill_header().is_err());
        assert!(admit_s19k_production_header_uses_workentry_prev(serial).is_ok());
        assert!(
            crate::s19k_bm1366_uart_rx::admit_s19k_production_classifies_init_rearm_rx(serial)
                .is_ok()
        );
    }

    #[test]
    fn s19k_fill_lookup_is_braiins_raw_not_esp_f8() {
        let share_src = include_str!("s19k_bm1366_share.rs");
        assert!(admit_s19k_production_fill_lookup_is_raw(share_src).is_ok());
        assert!(refuse_s19k_fill_overlay_f8_as_fun_0091c0a0().is_err());
        assert!(refuse_esp_f8_mask_as_braiins_fill_job_id(
            S19K_CONSTRUCTED_FILL_JOB_OR_CORE
        )
        .is_err());
        assert!(crate::s19k_braiins_job::admit_bosminer_fill_path_job_id_is_work_id_shl_log().is_ok());
        assert_eq!(
            crate::s19k_braiins_job::s19k_braiins_uart_work_id_from_rx_job_byte(
                S19K_CONSTRUCTED_FILL_JOB_OR_CORE,
                crate::s19k_braiins_job::s19k_braiins_fill_midstate_log()
            )
            .unwrap(),
            u64::from(S19K_CONSTRUCTED_FILL_JOB_OR_CORE)
        );
        let mut slots = S19kOutstandingFillTx::new();
        slots
            .insert_wire(s19k_fill_tx_prefix(S19K_CONSTRUCTED_FILL_JOB_ID).to_vec())
            .unwrap();
        assert!(s19k_fill_lookup_tx(S19K_CONSTRUCTED_FILL_JOB_OR_CORE, &slots).is_err());
        assert_eq!(
            s19k_fill_lookup_tx_esp_overlay_experimental(
                S19K_CONSTRUCTED_FILL_JOB_OR_CORE,
                &slots
            )
            .unwrap()
            .1,
            S19K_CONSTRUCTED_FILL_JOB_ID
        );
        slots
            .insert_wire(s19k_fill_tx_prefix(S19K_CONSTRUCTED_FILL_JOB_OR_CORE).to_vec())
            .unwrap();
        let hit = s19k_fill_lookup_tx(S19K_CONSTRUCTED_FILL_JOB_OR_CORE, &slots).unwrap();
        assert_eq!(hit.1, S19K_CONSTRUCTED_FILL_JOB_OR_CORE);
        assert!(admit_s19k_fill_lookup_uses_raw_job_byte(hit.1, hit.1).is_ok());
        assert!(admit_s19k_fill_lookup_uses_raw_job_byte(
            S19K_CONSTRUCTED_FILL_JOB_OR_CORE,
            S19K_CONSTRUCTED_FILL_JOB_ID
        )
        .is_err());
        assert!(crate::s19k_bm1366_uart_rx::admit_s19k_live88_held_bm1366_job_nonce().is_ok());
    }
}
