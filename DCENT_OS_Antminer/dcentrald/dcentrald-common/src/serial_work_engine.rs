//! Pure serial work-engine building blocks (ADR-0009 / P1-1 strangler).
//!
//! Full mining loops stay in `s19j_hybrid_mining` / `serial_mining` / `am3_bb_mining`
//! until fully extracted. This module holds **host-testable** state-machine
//! pieces: work-history rings, share dedup sets, job-id stepping, the
//! generation-keyed [`SerialMiningEngineBookkeeping`] façade, and pure
//! [`SerialBringUpPluginKind`] admission — so engines stop re-implementing
//! bookkeeping and stop forking bring-up identity as free-floating strings.
//!
//! # Status
//!
//! **PRODUCTION pure policy** for rings/dedup/cursors/façade/bring-up admit.
//! Hybrid dual-chain / primary serial / hybrid FPGA loops own
//! [`SerialWorkBookkeeping`]`<WorkEntry>` (job-id/nonce/vbits dedup).
//! `serial_mining` + FPGA `work_dispatcher` own generation-keyed bookkeeping via
//! [`SerialMiningEngineBookkeeping`]. Live UART/Stratum I/O and full bring-up
//! plugin *execution* remain outside this module (engine residual).

use crate::serial_work_policy::{
    generation_dedup_cutoff, generation_share_dedup_key, next_asic_job_id, serial_share_dedup_key,
    should_clear_seen_shares, should_prune_generation_seen, DEFAULT_SEEN_SHARES_CAP,
    DEFAULT_SERIAL_JOB_ID_STEP, DEFAULT_WORK_HISTORY_PER_ID, GENERATION_SEEN_RETAIN_WINDOW,
    GENERATION_SEEN_SOFT_CAP_DISPATCHER, GENERATION_SEEN_SOFT_CAP_SERIAL,
};
use std::collections::{BTreeSet, HashSet, VecDeque};

/// What changed at the serial receive boundary during one observation interval.
///
/// This deliberately separates bytes delivered by the UART driver from complete
/// frames accepted by the response assembler. A `WireOnlyProgress` interval is
/// therefore evidence of wire activity without frame completion (for example,
/// partial/garbled input or a framing mismatch), while `Silent` means the host
/// observed no receive bytes at all. Neither state claims a chip-side cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialRxIntervalState {
    FramedProgress,
    WireOnlyProgress,
    Silent,
    CounterReset,
}

impl SerialRxIntervalState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FramedProgress => "framed-progress",
            Self::WireOnlyProgress => "wire-only-progress",
            Self::Silent => "silent",
            Self::CounterReset => "counter-reset",
        }
    }

    /// Compact code for the serial actor → mining-loop atomic.
    /// `0xFF` is reserved for "no interval published yet".
    pub const fn as_code(self) -> u8 {
        match self {
            Self::Silent => 0,
            Self::WireOnlyProgress => 1,
            Self::FramedProgress => 2,
            Self::CounterReset => 3,
        }
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Silent),
            1 => Some(Self::WireOnlyProgress),
            2 => Some(Self::FramedProgress),
            3 => Some(Self::CounterReset),
            _ => None,
        }
    }
}

/// live438 wrap-5 / live434 wrap-4 MULTI death is host nonce-silent.
/// Parser interval is an orthogonal axis: wire-only bytes are not chip
/// silence, and framed-progress is not wrap-7 survival or replace.
pub fn s19k_track1_rx_death_parser_note(state: Option<SerialRxIntervalState>) -> &'static str {
    match state {
        None => "parser-unknown",
        Some(SerialRxIntervalState::Silent) => "host-silent",
        Some(SerialRxIntervalState::WireOnlyProgress) => "wire-only-no-frame",
        Some(SerialRxIntervalState::FramedProgress) => "framed-still-progress",
        Some(SerialRxIntervalState::CounterReset) => "counter-reset",
    }
}

/// Delta and classification for two cumulative serial receive observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialRxInterval {
    pub wire_bytes: u64,
    pub framed_responses: u64,
    pub state: SerialRxIntervalState,
}

/// Classify cumulative RX counters without mistaking parser silence for wire
/// silence. Counter regression is kept explicit rather than hidden by a
/// saturating subtraction so a backend replacement/reset cannot forge a quiet
/// interval.
pub fn classify_serial_rx_interval(
    previous_wire_bytes: u64,
    current_wire_bytes: u64,
    previous_framed_responses: u64,
    current_framed_responses: u64,
) -> SerialRxInterval {
    if current_wire_bytes < previous_wire_bytes
        || current_framed_responses < previous_framed_responses
    {
        return SerialRxInterval {
            wire_bytes: current_wire_bytes,
            framed_responses: current_framed_responses,
            state: SerialRxIntervalState::CounterReset,
        };
    }

    let wire_bytes = current_wire_bytes - previous_wire_bytes;
    let framed_responses = current_framed_responses - previous_framed_responses;
    let state = if framed_responses > 0 {
        SerialRxIntervalState::FramedProgress
    } else if wire_bytes > 0 {
        SerialRxIntervalState::WireOnlyProgress
    } else {
        SerialRxIntervalState::Silent
    };

    SerialRxInterval {
        wire_bytes,
        framed_responses,
        state,
    }
}

/// One stored work candidate keyed by ASIC job-id slot (pure common fields).
///
/// Engines that need richer match metadata (nbits, merkle, share_target) keep a
/// local entry type and store it in [`WorkHistoryRing`]`<T>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkHistoryEntry {
    pub pool_job_id: String,
    pub extranonce2: String,
    pub ntime: u32,
    /// Base version before chip rolling (when tracked).
    pub version: u32,
}

/// Per-slot ring of recent work for matching nonces back to pool jobs.
///
/// Generic over entry type so engines can keep rich `WorkEntry` structs while
/// sharing eviction / indexing / clear semantics (P1-1 strangler).
#[derive(Debug, Clone)]
pub struct WorkHistoryRing<T> {
    /// Indexed by low 8 bits of ASIC job id (or echoed job id).
    slots: Vec<VecDeque<T>>,
    depth: usize,
}

// clippy::indexing_slicing: `slots` is constructed as exactly `(0..256)` entries
// and every accessor takes `slot: u8`, so `slots[slot as usize]` is total by
// construction. Returning `Option` from `push`/`slot_len` would invent an
// unreachable failure mode in the work-history hot path.
#[allow(clippy::indexing_slicing)]
impl<T> WorkHistoryRing<T> {
    pub fn new(depth: usize) -> Self {
        let depth = depth.max(1);
        Self {
            slots: (0..256).map(|_| VecDeque::with_capacity(depth)).collect(),
            depth,
        }
    }

    pub fn with_default_depth() -> Self {
        Self::new(DEFAULT_WORK_HISTORY_PER_ID)
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn push(&mut self, slot: u8, entry: T) {
        let q = &mut self.slots[slot as usize];
        if q.len() >= self.depth {
            q.pop_front();
        }
        q.push_back(entry);
    }

    /// Most recent entry for a slot (nonce match starts here).
    pub fn latest(&self, slot: u8) -> Option<&T> {
        self.slots[slot as usize].back()
    }

    /// Iterate newest-first for a slot.
    pub fn iter_newest_first(&self, slot: u8) -> impl Iterator<Item = &T> {
        self.slots[slot as usize].iter().rev()
    }

    pub fn is_empty_slot(&self, slot: u8) -> bool {
        self.slots[slot as usize].is_empty()
    }

    /// Number of retained entries in a slot (debug / diagnostics).
    pub fn slot_len(&self, slot: u8) -> usize {
        self.slots[slot as usize].len()
    }

    pub fn clear_all(&mut self) {
        for q in &mut self.slots {
            q.clear();
        }
    }
}

impl<T: Clone> WorkHistoryRing<T> {
    /// live448 wrap-5 `retired_s19k_history = work_history.clone()` wiped
    /// wrap-4 leftover share_targets, so leftover_hit stayed 0 leftover_header=8.
    /// Merge POST-admit history into wrap-4 leftover generations.
    pub fn merge_from(&mut self, other: &Self) {
        for slot in 0u8..=255 {
            let oldest_first: Vec<T> = other
                .iter_newest_first(slot)
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            for entry in oldest_first {
                self.push(slot, entry);
            }
        }
    }
}

/// Bounded share-dedup set for serial paths.
#[derive(Debug, Clone)]
pub struct SeenShareSet {
    inner: BTreeSet<(u8, u32, u16)>,
    cap: usize,
}

impl Default for SeenShareSet {
    // Manual, NOT derived: a derived Default sets cap = 0, bypassing new()'s
    // `cap.max(1)` invariant. With cap = 0 the clear-at-cap check
    // (`should_clear_seen_shares(len, 0)` = `len > 0`) fires on every insert
    // BEFORE the membership test, so every share — including an immediate
    // duplicate — reads as new and the dedup is fully defeated (duplicate
    // submits to the pool). Route through the real constructor instead.
    fn default() -> Self {
        Self::with_default_cap()
    }
}

impl SeenShareSet {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: BTreeSet::new(),
            cap: cap.max(1),
        }
    }

    pub fn with_default_cap() -> Self {
        Self::new(DEFAULT_SEEN_SHARES_CAP)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns true if this is a **new** share (inserted).
    ///
    /// When over cap, clears **before** inserting so the just-accepted share
    /// is retained (SSOT vs ad-hoc post-insert wipe that dropped survivors).
    pub fn insert(&mut self, asic_job_id: u8, nonce: u32, version_bits: u16) -> bool {
        if should_clear_seen_shares(self.inner.len(), self.cap) {
            self.inner.clear();
        }
        self.inner
            .insert(serial_share_dedup_key(asic_job_id, nonce, version_bits))
    }

    pub fn contains(&self, asic_job_id: u8, nonce: u32, version_bits: u16) -> bool {
        self.inner
            .contains(&serial_share_dedup_key(asic_job_id, nonce, version_bits))
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

/// Generation-keyed share dedup (serial_mining + FPGA work_dispatcher).
///
/// Key: `(dispatch_generation, nonce, midstate_idx)`. Unlike [`SeenShareSet`],
/// over-cap eviction **retains** recent generations so nonces still in the UART
/// pipeline are not re-admitted as "new" after a wholesale wipe.
///
/// Callers collapse `midstate_idx` to 0 when version rolling is inactive so
/// identical multi-slot FPGA/serial copies map to one key.
#[derive(Debug, Clone)]
pub struct GenerationSeenShareSet {
    inner: HashSet<(u64, u32, u8)>,
    soft_cap: usize,
    retain_window: u64,
}

impl Default for GenerationSeenShareSet {
    fn default() -> Self {
        Self::serial_mining_defaults()
    }
}

impl GenerationSeenShareSet {
    pub fn new(soft_cap: usize, retain_window: u64) -> Self {
        Self {
            inner: HashSet::new(),
            soft_cap: soft_cap.max(1),
            retain_window: retain_window.max(1),
        }
    }

    /// `serial_mining` historical soft-cap 4096 + retain last 2048 generations.
    pub fn serial_mining_defaults() -> Self {
        Self::new(
            GENERATION_SEEN_SOFT_CAP_SERIAL,
            GENERATION_SEEN_RETAIN_WINDOW,
        )
    }

    /// FPGA `work_dispatcher` historical soft-cap 4000 + retain last 2048.
    pub fn dispatcher_defaults() -> Self {
        Self::new(
            GENERATION_SEEN_SOFT_CAP_DISPATCHER,
            GENERATION_SEEN_RETAIN_WINDOW,
        )
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn soft_cap(&self) -> usize {
        self.soft_cap
    }

    pub fn retain_window(&self) -> u64 {
        self.retain_window
    }

    /// Insert a candidate. Returns `true` if **new**.
    ///
    /// After a successful insert, if `len > soft_cap`, retains entries with
    /// `generation >= current_dispatch_generation.saturating_sub(retain_window)`.
    /// Duplicates do not prune (matches engine loops).
    pub fn insert(
        &mut self,
        generation: u64,
        nonce: u32,
        midstate_idx: u8,
        current_dispatch_generation: u64,
    ) -> bool {
        let key = generation_share_dedup_key(generation, nonce, midstate_idx);
        if !self.inner.insert(key) {
            return false;
        }
        if should_prune_generation_seen(self.inner.len(), self.soft_cap) {
            let cutoff = generation_dedup_cutoff(current_dispatch_generation, self.retain_window);
            self.inner.retain(|&(g, _, _)| g >= cutoff);
        }
        true
    }

    pub fn contains(&self, generation: u64, nonce: u32, midstate_idx: u8) -> bool {
        self.inner
            .contains(&generation_share_dedup_key(generation, nonce, midstate_idx))
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

/// Job-id stepper for serial / FPGA ASIC dispatch.
///
/// `mask` preserves engine-specific ranges (e.g. hybrid FPGA / serial_mining
/// use `0x7F`; full-u8 serial dual-chain uses `0xFF`).
#[derive(Debug, Clone, Copy)]
pub struct AsicJobIdCursor {
    current: u8,
    step: u8,
    mask: u8,
}

impl AsicJobIdCursor {
    pub fn new(start: u8, step: u8) -> Self {
        Self::with_mask(start, step, 0xFF)
    }

    pub fn with_mask(start: u8, step: u8, mask: u8) -> Self {
        let mask = if mask == 0 { 0xFF } else { mask };
        Self {
            current: start & mask,
            step: step.max(1),
            mask,
        }
    }

    /// AM2 serial dual-chain / proven serial step (full u8, step 8).
    pub fn default_serial() -> Self {
        Self::new(0, DEFAULT_SERIAL_JOB_ID_STEP)
    }

    /// Hybrid FPGA WORK_TX path: step 2, 7-bit work-id mask.
    pub fn hybrid_fpga() -> Self {
        Self::with_mask(0, 2, 0x7F)
    }

    /// serial_mining chip-family stride with 7-bit mask (BM1362/66/98).
    pub fn serial_mining(step: u8) -> Self {
        Self::with_mask(0, step, 0x7F)
    }

    /// S19k Braiins fill: midstates=1 ⇒ log 0 ⇒ UART registry `0x100>>0=256`,
    /// job_id=work_id identity (can emit 2). ESP `+8`/`0xF8` is a different
    /// dialect (`S19K_WIRE_JOB_ID_STEP`); do not shrink this cursor to 16 slots.
    pub fn s19k_braiins_fill() -> Self {
        Self::with_mask(0, 1, 0xFF)
    }

    pub fn current(self) -> u8 {
        self.current
    }

    pub fn step(self) -> u8 {
        self.step
    }

    pub fn mask(self) -> u8 {
        self.mask
    }

    /// Return current id, then advance with wrap + mask.
    pub fn take_and_advance(&mut self) -> u8 {
        let id = self.current;
        self.current = next_asic_job_id(self.current, self.step) & self.mask;
        id
    }
}

/// Pure engine bookkeeping bundle: history ring + job-id cursor + SeenShareSet.
///
/// Generic over history entry type so hybrid/serial engines keep rich
/// `WorkEntry` metadata while sharing clean-jobs / ownership semantics.
/// Default `T = WorkHistoryEntry` for pure host tests. Generation-keyed
/// serial_mining / work_dispatcher prefer [`SerialMiningEngineBookkeeping`].
#[derive(Debug, Clone)]
pub struct SerialWorkBookkeeping<T = WorkHistoryEntry> {
    pub history: WorkHistoryRing<T>,
    pub seen: SeenShareSet,
    pub job_ids: AsicJobIdCursor,
}

impl<T> SerialWorkBookkeeping<T> {
    /// AM2 serial dual-chain / primary serial-dispatch defaults (step 8, full u8).
    pub fn hybrid_defaults() -> Self {
        Self {
            history: WorkHistoryRing::with_default_depth(),
            seen: SeenShareSet::with_default_cap(),
            job_ids: AsicJobIdCursor::default_serial(),
        }
    }

    /// Hybrid FPGA WORK_TX path: 7-bit work-id + step 2.
    pub fn hybrid_fpga() -> Self {
        Self {
            history: WorkHistoryRing::with_default_depth(),
            seen: SeenShareSet::with_default_cap(),
            job_ids: AsicJobIdCursor::hybrid_fpga(),
        }
    }

    pub fn with_history_depth(depth: usize) -> Self {
        Self {
            history: WorkHistoryRing::new(depth),
            seen: SeenShareSet::with_default_cap(),
            job_ids: AsicJobIdCursor::default_serial(),
        }
    }

    pub fn with_job_cursor(job_ids: AsicJobIdCursor) -> Self {
        Self {
            history: WorkHistoryRing::with_default_depth(),
            seen: SeenShareSet::with_default_cap(),
            job_ids,
        }
    }

    /// History depth + job-id cursor (am3_bb Serial88/Asic86 codec presets).
    ///
    /// G13: engines that already chose a pure cursor should not hand-struct
    /// three separate bookkeeping locals — assemble the façade here.
    pub fn with_depth_and_cursor(depth: usize, job_ids: AsicJobIdCursor) -> Self {
        Self {
            history: WorkHistoryRing::new(depth),
            seen: SeenShareSet::with_default_cap(),
            job_ids,
        }
    }

    /// On clean_jobs / new block: drop history and dedup.
    pub fn on_clean_jobs(&mut self) {
        self.history.clear_all();
        self.seen.clear();
    }
}

// ---------------------------------------------------------------------------
// P1-1 SerialMiningEngine façade (generation-keyed path) + bring-up plugins
// ---------------------------------------------------------------------------

/// Maximum serial work frames per second per chain (pacing rule).
///
/// Engines translate this into dispatch timer intervals; pure constant keeps
/// three engines from inventing different flood limits offline.
pub const SERIAL_WORK_MAX_FRAMES_PER_SEC: u32 = 50;

/// Minimum inter-dispatch interval (ms) implied by [`SERIAL_WORK_MAX_FRAMES_PER_SEC`].
pub fn serial_work_min_interval_ms() -> u64 {
    // ceil(1000 / 50) = 20
    1000u64.div_ceil(u64::from(SERIAL_WORK_MAX_FRAMES_PER_SEC.max(1)))
}

/// Pure serial mining-engine bookkeeping (ADR-0009 / P1-1 façade seed).
///
/// Owns job-id cursor + generation-keyed share dedup + dispatch generation.
/// Work history stays engine-local when the entry type is richer than
/// [`WorkHistoryEntry`] (serial_mining `WorkEntry` with share targets).
///
/// # Status
///
/// **PRODUCTION pure policy.** `serial_mining` and FPGA `work_dispatcher`
/// construct this façade for generation-keyed paths. Hybrid job-id/nonce
/// paths use [`SerialWorkBookkeeping`]`<WorkEntry>` (same pure spine, different
/// dedup key — must not force generation keys onto hybrid BIP320 vbits dedup).
#[derive(Debug, Clone)]
pub struct SerialMiningEngineBookkeeping {
    pub job_ids: AsicJobIdCursor,
    pub seen: GenerationSeenShareSet,
    /// Monotonic dispatch generation for work→nonce matching + dedup prune.
    dispatch_generation: u64,
}

impl SerialMiningEngineBookkeeping {
    /// `serial_mining` path: 7-bit job-id mask, family job-id step, serial soft-cap.
    pub fn serial_mining(job_id_step: u8) -> Self {
        Self {
            job_ids: AsicJobIdCursor::serial_mining(job_id_step),
            seen: GenerationSeenShareSet::serial_mining_defaults(),
            dispatch_generation: 0,
        }
    }

    /// Braiins Track-1 fill: sequential work_id 0..255 (`0x100 >> log0`).
    pub fn s19k_braiins_fill() -> Self {
        Self {
            job_ids: AsicJobIdCursor::s19k_braiins_fill(),
            seen: GenerationSeenShareSet::serial_mining_defaults(),
            dispatch_generation: 0,
        }
    }

    /// FPGA `work_dispatcher` generation-keyed path (soft-cap 4000).
    ///
    /// Work IDs are ledger-owned (`ChainWorkLedger`); engines call
    /// [`take_generation`] for the dispatch serial and [`admit_share`] for
    /// nonce dedup. The embedded job-id cursor is unused on this path.
    pub fn work_dispatcher() -> Self {
        Self {
            job_ids: AsicJobIdCursor::hybrid_fpga(),
            seen: GenerationSeenShareSet::dispatcher_defaults(),
            dispatch_generation: 0,
        }
    }

    pub fn dispatch_generation(&self) -> u64 {
        self.dispatch_generation
    }

    /// Take next ASIC job id **and** the generation that will tag this dispatch.
    ///
    /// Advances both the job-id cursor and the generation counter after
    /// returning — matching engines that stamp work with the current generation
    /// then increment for the next item.
    pub fn take_dispatch(&mut self) -> SerialDispatchTicket {
        let job_id = self.job_ids.take_and_advance();
        let generation = self.dispatch_generation;
        self.dispatch_generation = self.dispatch_generation.saturating_add(1);
        SerialDispatchTicket { job_id, generation }
    }

    /// Take next dispatch generation only (FPGA `work_dispatcher` path).
    ///
    /// Work IDs come from per-chain ledgers; only the monotonic generation tags
    /// ledger rows and generation-keyed share dedup.
    pub fn take_generation(&mut self) -> u64 {
        let generation = self.dispatch_generation;
        self.dispatch_generation = self.dispatch_generation.saturating_add(1);
        generation
    }

    /// Admit a nonce share: `true` if new (not a duplicate under retain-prune).
    pub fn admit_share(&mut self, work_generation: u64, nonce: u32, midstate_idx: u8) -> bool {
        self.seen.insert(
            work_generation,
            nonce,
            midstate_idx,
            self.dispatch_generation,
        )
    }

    /// Clean-jobs / new-block: clear generation dedup (history is engine-owned).
    pub fn on_clean_jobs(&mut self) {
        self.seen.clear();
    }

    /// Track-1 mid-run clean: restart fill `0..255`. live414/417/418 left the
    /// cursor running after `clean_jobs`, so new midstates reused later slots
    /// while chips kept hashing the pre-clean first-load jobs.
    pub fn reset_s19k_braiins_fill(&mut self) {
        *self = Self::s19k_braiins_fill();
    }
}

/// /424: post-clean share-funnel counters for S19k Track-1.
///
/// live414/417/418: after the first mid-run `clean_jobs`, ticket nonces keep
/// correlating (`JobNonceFillOk` at the full TX pace) but none ever pass the
/// pool-target check. live412 `...8bd1` is **not** occupied-slot replace
/// proof — that notify arrived ~65 TX into the first 256-slot fill. Session
/// start shares also follow GetAddress/discover (live415 died when that was
/// tried mid-run). The remaining question is whether post-clean ticket
/// nonces still solve the **retired** pre-clean generation. These counters
/// plus the nonce/TX dump make that desk-decidable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct S19kCleanFunnel {
    /// Mid-run cleans observed since run start (session-start job excluded).
    pub cleans: u32,
    /// Tagged BM1366 RX bodies that entered the nonce branch since last clean.
    pub rxs: u32,
    /// `hunt_s19k_bm1366_fill_from_tagged_slot` refused (not counted at all).
    pub correlate_fail: u32,
    /// Counted, but no retry slot had a work-history entry.
    pub history_stale: u32,
    /// Counted with history, but `serial_rolled_version` returned None.
    pub version_none: u32,
    /// Header hash met the pool share target.
    pub meets: u32,
    /// Header hash below the **current** post-clean target.
    pub misses: u32,
    /// Missed the new target, but met a retired pre-clean **21 36 wire**.
    pub leftover_hit: u32,
    /// Header-history leftover that did **not** hash a retired 21 36 wire
    /// (live425 `LeftoverPreClean` + `retired_tx_meets=false`).
    pub leftover_header: u32,
    /// Missed both the new target and every retired slot.
    pub unknown_miss: u32,
    /// Nonce/TX dump lines still owed after the latest clean.
    pub dumps_left: u32,
    /// First post-clean `21 36` TX still owed (session `total_work` is not reset).
    pub frame_dump_owed: bool,
}

impl S19kCleanFunnel {
    /// Nonces to dump per clean for offline hash-verification.
    pub const DUMPS_PER_CLEAN: u32 = 24;

    /// A new mid-run clean: reset per-clean stages, re-arm the dump budget.
    pub fn on_clean(&mut self) {
        self.cleans = self.cleans.saturating_add(1);
        self.rxs = 0;
        self.correlate_fail = 0;
        self.history_stale = 0;
        self.version_none = 0;
        self.meets = 0;
        self.misses = 0;
        self.leftover_hit = 0;
        self.leftover_header = 0;
        self.unknown_miss = 0;
        self.dumps_left = Self::DUMPS_PER_CLEAN;
        self.frame_dump_owed = true;
    }

    /// Snapshot leftover/meets **before** `on_clean` wipes them. The
    /// second mid-run clean must plan from the first clean's leftover
    /// (live431 leftover_hit=4). Planning after `on_clean` always sees 0.
    pub fn snapshot_for_post_clean_plan(&self) -> (u32, u32, u32) {
        (self.leftover_hit, self.leftover_header, self.meets)
    }

    /// After leftover-admitted Chain Inactive, leftover/meets must
    /// measure the post-flush generation. Do not increment `cleans`
    /// (that is a pool clean, not a flush).
    pub fn on_leftover_admitted_inactive(&mut self) {
        self.rxs = 0;
        self.correlate_fail = 0;
        self.history_stale = 0;
        self.version_none = 0;
        self.meets = 0;
        self.misses = 0;
        self.leftover_hit = 0;
        self.leftover_header = 0;
        self.unknown_miss = 0;
        self.dumps_left = Self::DUMPS_PER_CLEAN;
        self.frame_dump_owed = true;
    }
}

/// wrap-4 early snapshot calls [`S19kCleanFunnel::on_clean`], which
/// wipes leftover_hit. Restore wrap-retire leftover so leftover-admitted
/// inactive can still fire on the next tick.
pub fn s19k_restore_wrap_retire_leftover_after_clean_snapshot(
    funnel: &mut S19kCleanFunnel,
    leftover_hit: u32,
    leftover_header: u32,
    meets: u32,
) {
    funnel.leftover_hit = leftover_hit;
    funnel.leftover_header = leftover_header;
    funnel.meets = meets;
}

pub fn admit_s19k_wrap4_snapshot_preserves_wrap_retire_leftover() -> Result<(), &'static str> {
    let mut funnel = S19kCleanFunnel::default();
    funnel.leftover_hit = crate::s19k_braiins_job::S19K_LIVE431_LEFTOVER_HIT;
    funnel.leftover_header = crate::s19k_braiins_job::S19K_LIVE431_LEFTOVER_HEADER;
    funnel.meets = crate::s19k_braiins_job::S19K_LIVE431_MEETS;
    let (hit, header, meets) = funnel.snapshot_for_post_clean_plan();
    funnel.on_clean();
    if funnel.leftover_hit != 0 {
        return Err("on_clean must wipe leftover_hit before restore");
    }
    s19k_restore_wrap_retire_leftover_after_clean_snapshot(&mut funnel, hit, header, meets);
    if funnel.leftover_hit != crate::s19k_braiins_job::S19K_LIVE431_LEFTOVER_HIT {
        return Err("wrap-4 snapshot must restore wrap-retire leftover_hit");
    }
    if !crate::s19k_braiins_job::s19k_leftover_hit_admits_experimental_inactive(
        funnel.leftover_hit,
        funnel.leftover_header,
        funnel.meets,
    ) {
        return Err("restored wrap-retire leftover must still admit leftover-admitted inactive");
    }
    if funnel.cleans != 1 {
        return Err("wrap-4 snapshot still arms the funnel");
    }
    Ok(())
}

impl S19kCleanFunnel {
    /// Consume one dump slot; `false` once the per-clean budget is spent.
    pub fn take_dump(&mut self) -> bool {
        if self.dumps_left == 0 {
            return false;
        }
        self.dumps_left -= 1;
        true
    }

    /// live425: the 24-slot budget was spent on ticket-256 UnknownMiss, so
    /// the six leftover_hit pool-valid nonces were never dumped. Leftover
    /// and new-block classes always dump; UnknownMiss still uses the budget.
    pub fn take_dump_for(&mut self, class: S19kPostCleanNonceClass) -> bool {
        match class {
            S19kPostCleanNonceClass::LeftoverPreClean | S19kPostCleanNonceClass::NewBlockShare => {
                true
            }
            S19kPostCleanNonceClass::UnknownMiss => self.take_dump(),
        }
    }

    /// Consume the one-shot post-clean FULL FRAME dump.
    pub fn take_frame_dump(&mut self) -> bool {
        if !self.frame_dump_owed {
            return false;
        }
        self.frame_dump_owed = false;
        true
    }
}

/// live412/414 only logged `FULL FRAME` when `total_work <= 1`. Mid-run
/// clean does not reset that counter, so post-clean TX never hit the log.
/// Dump the session-first frame **or** the first frame after a mid-run clean.
pub fn s19k_should_log_full_work_frame(total_work: u64, post_clean_frame_owed: bool) -> bool {
    // Call site increments first: session-first work is `total_work == 1`.
    total_work == 1 || post_clean_frame_owed
}

/// `true` only after a mid-run clean (the session-start job is not a cliff risk).
pub fn s19k_clean_funnel_armed(funnel: &S19kCleanFunnel) -> bool {
    funnel.cleans > 0
}

/// Production pin: the serial nonce path must count every funnel stage and
/// dump post-clean nonce/TX pairs ( discriminator for the cliff).
pub fn admit_s19k_production_clean_funnel_instrumented(src: &str) -> Result<(), &'static str> {
    if !src.contains("clean_funnel.on_clean()") {
        return Err("serial_mining clean path must arm the S19k clean funnel");
    }
    if !src.contains("snapshot_for_post_clean_plan") {
        return Err(
            "second clean must plan leftover from pre-reset snapshot (live431 leftover_hit=4)",
        );
    }
    if !src.contains("on_leftover_admitted_inactive") {
        return Err("leftover-admitted inactive must reset leftover/meets for the post-flush bar");
    }
    if !src.contains("s19k_post_inactive_replace_proven") {
        return Err("funnel line must compute replace_proven from post-inactive leftover vs meets");
    }
    if !src.contains("s19k_post_inactive_flush_measured_not_replace") {
        return Err("funnel line must distinguish leftover-admit flush from replace (live438 leftover_hit=0)");
    }
    if !src.contains("flush_measured") {
        return Err("funnel line must print flush_measured");
    }
    if !src.contains("replace_proven") {
        return Err("funnel line must print replace_proven");
    }
    if !src.contains("let midrun_clean = is_bm1366 && total_work > 0") {
        return Err(
            "funnel must arm only after the first work (session-start clean is not the cliff)",
        );
    }
    if !src.contains("clean_funnel.take_dump_for(") {
        return Err("serial_mining nonce path must dump leftover/meets even after the 24 UnknownMiss budget");
    }
    if !src.contains("S19k post-clean funnel") {
        return Err("serial_mining must log the post-clean funnel line");
    }
    if !src.contains("S19k post-clean nonce dump") {
        return Err("serial_mining must log the post-clean nonce dump line");
    }
    if !src.contains("classify_s19k_post_clean_nonce") {
        return Err("serial_mining must classify leftover vs new-block after clean");
    }
    if !src.contains("leftover_hit") {
        return Err("serial_mining must count leftover_hit against retired history");
    }
    if !src.contains("s19k_track1_count_wrap_retire_leftover") {
        return Err("leftover_hit must count wrap-retire leftover before funnel arm");
    }
    if !src.contains("s19k_restore_wrap_retire_leftover_after_clean_snapshot") {
        return Err("wrap-4 snapshot must restore wrap-retire leftover after on_clean");
    }
    if !src.contains("S19k wrap-retire leftover") {
        return Err("alive tick must print wrap-retire leftover before first clean");
    }
    if !src.contains("s19k_post_clean_submit_allowed") {
        return Err("serial_mining must refuse leftover/ambiguous post-clean submits");
    }
    if !src.contains("retired_s19k_tx") {
        return Err("serial_mining must snapshot outstanding TX on mid-run clean");
    }
    if !src.contains("retired_tx_wire") {
        return Err("serial_mining leftover dump must include the retired pre-clean TX");
    }
    if !src.contains("s19k_should_log_full_work_frame") {
        return Err("serial_mining must dump the first post-clean FULL FRAME");
    }
    if !src.contains("s19k_compact_tx_meets_share_target") {
        return Err("serial_mining leftover dump must hash nonce vs unpacked TX");
    }
    if !src.contains("s19k_first_tx_hex_where") {
        return Err("leftover class/dump must search retired TX wires, not first-occupied");
    }
    if !src.contains("s19k_leftover_hit_from_retired_store") {
        return Err(
            "leftover_hit must use s19k_leftover_hit_from_retired_store on retired 21 36 wires",
        );
    }
    if !src.contains("s19k_leftover_class_matches_retired_tx") {
        return Err("serial_mining must pin leftover class to the same retired TX meet");
    }
    if !src.contains("leftover_header") {
        return Err("serial_mining must count header-only leftover separately from TX leftover");
    }
    if !src.contains("s19k_leftover_header_is_not_tx_leftover") {
        return Err("leftover_header increment must use s19k_leftover_header_is_not_tx_leftover (live438 leftover_header=3 leftover_hit=0)");
    }
    if !src.contains("nonce_silent_s") {
        return Err("serial_mining alive line must print nonce_silent_s");
    }
    if !src.contains("new_tx_meets") || !src.contains("retired_tx_meets") {
        return Err("serial_mining leftover dump must log new_tx_meets and retired_tx_meets");
    }
    Ok(())
}

/// : a post-clean ticket nonce either meets the new template,
/// still solves the retired pre-clean slot (leftover), or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kPostCleanNonceClass {
    NewBlockShare,
    LeftoverPreClean,
    UnknownMiss,
}

pub fn classify_s19k_post_clean_nonce(
    new_meets: bool,
    retired_meets: bool,
) -> S19kPostCleanNonceClass {
    // Both-meet is remapped leftover (new job_id, old work still hashes).
    // Must match `s19k_post_clean_submit_allowed`.
    if retired_meets {
        S19kPostCleanNonceClass::LeftoverPreClean
    } else if new_meets {
        S19kPostCleanNonceClass::NewBlockShare
    } else {
        S19kPostCleanNonceClass::UnknownMiss
    }
}

/// Leftover-safe submit: only a nonce that meets the **new** template and
/// does **not** still solve the retired pre-clean slot may go to the pool.
/// Both-meet is treated as remapped leftover, not a new-block share.
pub fn s19k_post_clean_submit_allowed(new_meets: bool, retired_meets: bool) -> bool {
    new_meets && !retired_meets
}

/// One pure dispatch assignment from [`SerialMiningEngineBookkeeping::take_dispatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialDispatchTicket {
    pub job_id: u8,
    pub generation: u64,
}

/// Pure serial bring-up plugin identity (ADR-0009 BoardBringUp seed).
///
/// Engines select a plugin kind from BoardDesc protocol×transport, then
/// [`SerialBringUpPlugin::plan`] / [`SerialBringUpPlugin::execute`] over pure
/// [`crate::chain_transport::TransportOp`] sequences. Live UART open, voltage
/// rail, and PLL register tables remain engine/HAL residual.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SerialBringUpPluginKind {
    /// AM2 Zynq hybrid/serial BM1362 (XIL S19j Pro class).
    Am2ZynqBm1362,
    /// AM3 BeagleBone BM1362.
    Am3BbBm1362,
    /// Amlogic BM1366 serial.
    AmlogicBm1366,
    /// Amlogic BM1368 serial.
    AmlogicBm1368,
    /// Amlogic BM1370 serial.
    AmlogicBm1370,
    /// BM1398 serial class (when admitted on serial transport).
    SerialBm1398,
    /// AM2 Zynq hybrid BM1397 (S17/S17+/T17/T17+ class; 2026-08-27
    /// `2026-08-27-antminer17-unlock-armada` promotion). Speaks the BM1397+
    /// command surface (ChainInactive/GetAddress/SetAddress) with the
    /// `floor(256/N)` address stride and the 4-midstate AsicBoost job codec —
    /// NOT BIP320 version rolling.
    Am2ZynqBm1397,
}

impl SerialBringUpPluginKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Am2ZynqBm1362 => "am2_zynq_bm1362",
            Self::Am3BbBm1362 => "am3_bb_bm1362",
            Self::AmlogicBm1366 => "amlogic_bm1366",
            Self::AmlogicBm1368 => "amlogic_bm1368",
            Self::AmlogicBm1370 => "amlogic_bm1370",
            Self::SerialBm1398 => "serial_bm1398",
            Self::Am2ZynqBm1397 => "am2_zynq_bm1397",
        }
    }

    /// Default job-id step for this plugin's serial mining path when known.
    pub const fn default_job_id_step(self) -> u8 {
        match self {
            Self::SerialBm1398 => 4, // historical BM1398 midstate stride class
            // BM1397 4-midstate AsicBoost: job-id +4 mod 128 (ESP-Miner
            // `for_bm1397` dispatcher; dcentaxe-asic).
            Self::Am2ZynqBm1397 => 4,
            _ => DEFAULT_SERIAL_JOB_ID_STEP,
        }
    }

    /// ASIC protocol identity this plugin speaks (composition SSOT).
    pub const fn asic_protocol(self) -> crate::board_desc::AsicProtocolIdentity {
        use crate::board_desc::AsicProtocolIdentity;
        match self {
            Self::Am2ZynqBm1362 | Self::Am3BbBm1362 => AsicProtocolIdentity::Bm1362,
            Self::AmlogicBm1366 => AsicProtocolIdentity::Bm1366,
            Self::AmlogicBm1368 => AsicProtocolIdentity::Bm1368,
            Self::AmlogicBm1370 => AsicProtocolIdentity::Bm1370,
            Self::SerialBm1398 => AsicProtocolIdentity::Bm1398,
            Self::Am2ZynqBm1397 => AsicProtocolIdentity::Bm1397,
        }
    }
}

// ---------------------------------------------------------------------------
// P1-1 BoardBringUp-shaped serial plugin: plan + execute TransportOps
// ---------------------------------------------------------------------------

/// Pure parameters for serial BM1397+-class bring-up planning (no I/O).
///
/// Dwell timings match historical engine policy (≈300 ms inactive settle) so
/// plans are host-testable without inventing PLL register values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialBringUpPlanParams {
    /// Expected chip count for the address ladder (0 = enumerate-only).
    pub chip_count: u8,
    /// Frequency intent (MHz). Offline plans **never** expand this to register
    /// writes — PLL tables stay in silicon-profiles / engine residual.
    pub frequency_mhz: u16,
    /// ChainInactive burst count before GetAddress (BM1397+ soft-reset class).
    pub chain_inactive_count: u8,
    /// Delay after each ChainInactive (ms). 0 = no dwell ops.
    pub inactive_dwell_ms: u32,
    /// Delay after GetAddress before the address ladder (ms). 0 = none.
    pub post_enum_delay_ms: u32,
}

impl Default for SerialBringUpPlanParams {
    fn default() -> Self {
        Self {
            chip_count: 0,
            frequency_mhz: 0,
            chain_inactive_count: 3,
            inactive_dwell_ms: 300,
            post_enum_delay_ms: 100,
        }
    }
}

impl SerialBringUpPlanParams {
    pub fn with_chip_count(chip_count: u8) -> Self {
        Self {
            chip_count,
            ..Self::default()
        }
    }
}

/// Ordered pure bring-up plan produced by a [`SerialBringUpPlugin`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialBringUpPlan {
    pub plugin: SerialBringUpPluginKind,
    pub admission: crate::asic_protocol::ProtocolTransportAdmission,
    pub ops: Vec<crate::chain_transport::TransportOp>,
    /// True when `frequency_mhz > 0` but PLL ops were intentionally omitted.
    pub frequency_program_deferred: bool,
}

impl SerialBringUpPlan {
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Split the flat op list into engine-adoptable phases (no reordering).
    ///
    /// Live engines historically run ChainInactive, then register/probe work,
    /// then SetAddress — not always the contiguous full plan. Phases let them
    /// adopt pure planners without forcing GetAddress into a new slot.
    pub fn phases(&self) -> SerialBringUpPhases {
        use crate::chain_transport::TransportOp;
        let mut soft_reset = Vec::new();
        let mut enumerate = Vec::new();
        let mut address_ladder = Vec::new();
        let mut other = Vec::new();
        let mut seen_get_address = false;
        let mut seen_set_address = false;
        for op in &self.ops {
            match op {
                TransportOp::SendChainInactiveBm1397Plus
                    if !seen_get_address && !seen_set_address =>
                {
                    soft_reset.push(op.clone());
                }
                TransportOp::DelayMs { .. }
                    if !seen_get_address && !seen_set_address && !soft_reset.is_empty() =>
                {
                    // Dwells after inactive stay in soft_reset until enum starts.
                    soft_reset.push(op.clone());
                }
                TransportOp::SendGetAddressBm1397Plus => {
                    seen_get_address = true;
                    enumerate.push(op.clone());
                }
                TransportOp::DelayMs { .. } if seen_get_address && !seen_set_address => {
                    enumerate.push(op.clone());
                }
                TransportOp::SendSetAddressBm1397Plus { .. } => {
                    seen_set_address = true;
                    address_ladder.push(op.clone());
                }
                other_op => other.push(other_op.clone()),
            }
        }
        SerialBringUpPhases {
            soft_reset,
            enumerate,
            address_ladder,
            other,
        }
    }
}

/// Engine-adoptable phases of a [`SerialBringUpPlan`] (pure, no I/O).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SerialBringUpPhases {
    /// ChainInactive (+ optional dwells) before enumeration.
    pub soft_reset: Vec<crate::chain_transport::TransportOp>,
    /// GetAddress (+ optional post-enum dwell).
    pub enumerate: Vec<crate::chain_transport::TransportOp>,
    /// Full-population SetAddress ladder only.
    pub address_ladder: Vec<crate::chain_transport::TransportOp>,
    /// Anything else (should be empty for current pure plans).
    pub other: Vec<crate::chain_transport::TransportOp>,
}

/// Why pure serial bring-up planning/execution failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialBringUpPlanError {
    Admit(SerialBringUpAdmitError),
    ProtocolTransport(crate::asic_protocol::ProtocolTransportError),
    Transport(crate::chain_transport::TransportOpError),
    /// `ChainTransport::transport_kind` does not match the planned admission.
    TransportKindMismatch {
        planned: crate::board_desc::ChainTransportKind,
        actual: crate::board_desc::ChainTransportKind,
    },
}

impl std::fmt::Display for SerialBringUpPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admit(e) => write!(f, "serial bring-up plan: {e}"),
            Self::ProtocolTransport(e) => write!(f, "serial bring-up plan: {e}"),
            Self::Transport(e) => write!(f, "serial bring-up plan: {e}"),
            Self::TransportKindMismatch { planned, actual } => write!(
                f,
                "serial bring-up plan: transport kind mismatch planned={planned:?} actual={actual:?}"
            ),
        }
    }
}

impl std::error::Error for SerialBringUpPlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admit(e) => Some(e),
            Self::ProtocolTransport(e) => Some(e),
            Self::Transport(e) => Some(e),
            Self::TransportKindMismatch { .. } => None,
        }
    }
}

/// ADR-0009 BoardBringUp seed: pure plan + execute over [`ChainTransport`].
///
/// # Status
///
/// **PRODUCTION pure policy** for BM1397+-class ChainInactive / GetAddress /
/// full-population SetAddress ladder. PLL register programming is **NOT
/// IMPLEMENTED** offline (`frequency_program_deferred`). Live engine adapters
/// that open UART and sleep dwells remain **EXPERIMENTAL** residual until
/// wired end-to-end on a host-mock or Linux CI path.
pub trait SerialBringUpPlugin {
    fn kind(&self) -> SerialBringUpPluginKind;

    /// Plan admitted TransportOps for this plugin over `transport` (no I/O).
    fn plan(
        &self,
        transport: crate::board_desc::ChainTransportKind,
        params: &SerialBringUpPlanParams,
    ) -> Result<SerialBringUpPlan, SerialBringUpPlanError>;

    /// Plan then execute on a [`crate::chain_transport::ChainTransport`] adapter.
    fn execute(
        &self,
        transport: &mut impl crate::chain_transport::ChainTransport,
        params: &SerialBringUpPlanParams,
    ) -> Result<SerialBringUpPlan, SerialBringUpPlanError> {
        let plan = self.plan(transport.transport_kind(), params)?;
        if transport.transport_kind() != plan.admission.transport() {
            return Err(SerialBringUpPlanError::TransportKindMismatch {
                planned: plan.admission.transport(),
                actual: transport.transport_kind(),
            });
        }
        for op in &plan.ops {
            crate::chain_transport::admit_transport_op(plan.admission, op)
                .map_err(SerialBringUpPlanError::Transport)?;
            transport
                .execute_op(op)
                .map_err(SerialBringUpPlanError::Transport)?;
        }
        Ok(plan)
    }
}

/// Plan BM1397+-class serial bring-up ops (ChainInactive burst → GetAddress →
/// optional delay → full-population address ladder).
///
/// Shared by all [`SerialBringUpPluginKind`] variants that speak the BM1397+
/// command surface (BM1362/66/68/70/1398). Soft-reset uses
/// [`crate::chain_transport::plan_bm1397plus_chain_inactive_burst`]; address
/// assign uses [`crate::chain_transport::plan_bm1397plus_full_population_address_ladder`].
pub fn plan_serial_bring_up(
    plugin: SerialBringUpPluginKind,
    transport: crate::board_desc::ChainTransportKind,
    params: &SerialBringUpPlanParams,
) -> Result<SerialBringUpPlan, SerialBringUpPlanError> {
    use crate::asic_protocol::admit_protocol_over_transport;
    use crate::chain_transport::{
        admit_transport_op, plan_bm1397plus_chain_inactive_burst,
        plan_bm1397plus_full_population_address_ladder, plan_bm1397plus_set_address_ladder,
        protocol_speaks_bm1397plus_commands, TransportOp,
    };

    // Plugin must be admissible for this transport (protocol×transport matrix).
    let admitted = admit_serial_bring_up_plugin(plugin.asic_protocol(), transport)
        .map_err(SerialBringUpPlanError::Admit)?;
    // Family refine is identity for non-BB; BB refine is applied by callers
    // before plan when BoardFamily is known. Refuse if caller passes a plugin
    // that does not match the protocol×transport admit result after refine
    // would be applied elsewhere — here we only check protocol family.
    let _ = admitted;

    let admission = admit_protocol_over_transport(plugin.asic_protocol(), transport)
        .map_err(SerialBringUpPlanError::ProtocolTransport)?;

    if !protocol_speaks_bm1397plus_commands(plugin.asic_protocol()) {
        // Future non-BM1397+ plugins would branch here; all current kinds speak it.
        return Ok(SerialBringUpPlan {
            plugin,
            admission,
            ops: Vec::new(),
            frequency_program_deferred: params.frequency_mhz > 0,
        });
    }

    let mut ops: Vec<TransportOp> = Vec::new();

    // Soft-reset class: ChainInactive × N with optional dwell after each.
    let inactive_n = params.chain_inactive_count.max(1);
    for op in plan_bm1397plus_chain_inactive_burst(inactive_n) {
        ops.push(op);
        if params.inactive_dwell_ms > 0 {
            ops.push(TransportOp::DelayMs {
                ms: params.inactive_dwell_ms,
            });
        }
    }

    // Enumerate.
    ops.push(TransportOp::SendGetAddressBm1397Plus);
    if params.post_enum_delay_ms > 0 {
        ops.push(TransportOp::DelayMs {
            ms: params.post_enum_delay_ms,
        });
    }

    // Full-population address ladder when chip_count known.
    if params.chip_count > 0 {
        if plugin == SerialBringUpPluginKind::AmlogicBm1366 {
            ops.extend(plan_bm1397plus_set_address_ladder(
                params.chip_count,
                crate::s19k_bm1366_wire_b::S19K_AML_ADDR_INTERVAL,
            ));
        } else {
            ops.extend(plan_bm1397plus_full_population_address_ladder(
                params.chip_count,
            ));
        }
    }

    // PLL is intentionally not expanded offline.
    let frequency_program_deferred = params.frequency_mhz > 0;

    for op in &ops {
        admit_transport_op(admission, op).map_err(SerialBringUpPlanError::Transport)?;
    }

    Ok(SerialBringUpPlan {
        plugin,
        admission,
        ops,
        frequency_program_deferred,
    })
}

/// Execute a pre-built plan on a transport (re-admits each op; fail-closed).
pub fn execute_serial_bring_up_plan(
    transport: &mut impl crate::chain_transport::ChainTransport,
    plan: &SerialBringUpPlan,
) -> Result<(), SerialBringUpPlanError> {
    if transport.transport_kind() != plan.admission.transport() {
        return Err(SerialBringUpPlanError::TransportKindMismatch {
            planned: plan.admission.transport(),
            actual: transport.transport_kind(),
        });
    }
    for op in &plan.ops {
        crate::chain_transport::admit_transport_op(plan.admission, op)
            .map_err(SerialBringUpPlanError::Transport)?;
        transport
            .execute_op(op)
            .map_err(SerialBringUpPlanError::Transport)?;
    }
    Ok(())
}

/// BoardDesc → refined plugin → pure bring-up plan (no I/O).
pub fn plan_serial_bring_up_for_board(
    board: &crate::board_desc::BoardDesc,
    params: &SerialBringUpPlanParams,
) -> Result<SerialBringUpPlan, SerialBringUpPlanError> {
    let raw = admit_serial_bring_up_plugin(board.asic_protocol, board.chain_transport)
        .map_err(SerialBringUpPlanError::Admit)?;
    let plugin = refine_bm1362_bring_up_for_board_family(raw, board.family);
    plan_serial_bring_up(plugin, board.chain_transport, params)
}

impl SerialBringUpPlugin for SerialBringUpPluginKind {
    fn kind(&self) -> SerialBringUpPluginKind {
        *self
    }

    fn plan(
        &self,
        transport: crate::board_desc::ChainTransportKind,
        params: &SerialBringUpPlanParams,
    ) -> Result<SerialBringUpPlan, SerialBringUpPlanError> {
        plan_serial_bring_up(*self, transport, params)
    }
}

/// Why serial bring-up plugin admission failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialBringUpAdmitError {
    ManagementOnlyTransport,
    RuntimeDiscoveredProtocol,
    UnsupportedComposition {
        protocol: crate::board_desc::AsicProtocolIdentity,
        transport: crate::board_desc::ChainTransportKind,
    },
}

impl std::fmt::Display for SerialBringUpAdmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManagementOnlyTransport => {
                write!(f, "serial bring-up refused: management-only transport")
            }
            Self::RuntimeDiscoveredProtocol => write!(
                f,
                "serial bring-up refused: RuntimeDiscovered protocol needs measured identity"
            ),
            Self::UnsupportedComposition {
                protocol,
                transport,
            } => write!(
                f,
                "serial bring-up refused: no plugin for {protocol:?} over {transport:?}"
            ),
        }
    }
}

impl std::error::Error for SerialBringUpAdmitError {}

/// Admit which pure serial bring-up plugin applies (no I/O).
///
/// Derived from BoardDesc protocol×transport evidence. Prefer this over
/// open-coding `is_bm1362` / `is_bm1366` forks when selecting bring-up identity.
pub fn admit_serial_bring_up_plugin(
    protocol: crate::board_desc::AsicProtocolIdentity,
    transport: crate::board_desc::ChainTransportKind,
) -> Result<SerialBringUpPluginKind, SerialBringUpAdmitError> {
    use crate::board_desc::{AsicProtocolIdentity, ChainTransportKind};

    if matches!(transport, ChainTransportKind::None) {
        return Err(SerialBringUpAdmitError::ManagementOnlyTransport);
    }
    if matches!(protocol, AsicProtocolIdentity::RuntimeDiscovered) {
        return Err(SerialBringUpAdmitError::RuntimeDiscoveredProtocol);
    }

    match (protocol, transport) {
        (
            AsicProtocolIdentity::Bm1362,
            ChainTransportKind::ZynqHybrid | ChainTransportKind::Serial,
        ) => {
            // Zynq hybrid + serial both use the AM2 BM1362 bring-up family;
            // AM3-BB is also BM1362+Serial but distinguished by BoardDesc family
            // at a higher layer. Pure admit here is protocol×transport only.
            Ok(SerialBringUpPluginKind::Am2ZynqBm1362)
        }
        (AsicProtocolIdentity::Bm1362, ChainTransportKind::UartTrans) => {
            // CV evidence / uart_trans rows — still BM1362 serial-class framing.
            Ok(SerialBringUpPluginKind::Am2ZynqBm1362)
        }
        (
            AsicProtocolIdentity::Bm1366,
            ChainTransportKind::Serial | ChainTransportKind::UartTrans,
        ) => Ok(SerialBringUpPluginKind::AmlogicBm1366),
        (
            AsicProtocolIdentity::Bm1368,
            ChainTransportKind::Serial | ChainTransportKind::UartTrans,
        ) => Ok(SerialBringUpPluginKind::AmlogicBm1368),
        (
            AsicProtocolIdentity::Bm1370,
            ChainTransportKind::Serial | ChainTransportKind::UartTrans,
        ) => Ok(SerialBringUpPluginKind::AmlogicBm1370),
        (
            AsicProtocolIdentity::Bm1398,
            ChainTransportKind::Serial
            | ChainTransportKind::ZynqHybrid
            | ChainTransportKind::UartTrans,
        ) => Ok(SerialBringUpPluginKind::SerialBm1398),
        // 2026-08-27 S17 hybrid promotion (`2026-08-27-antminer17-unlock-armada`,
        // agent B1): BM1397 on the Zynq hybrid carrier gets its own plugin kind.
        // The pure plan is the shared BM1397+ surface (ChainInactive burst →
        // GetAddress → floor(256/N) SetAddress ladder); the family recipe
        // (MiscCtrl 0x18 baud ladder, 4-midstate job codec) lives in the
        // dcentrald S17 hybrid engine, not here.
        (
            AsicProtocolIdentity::Bm1397,
            ChainTransportKind::ZynqHybrid
            | ChainTransportKind::Serial
            | ChainTransportKind::UartTrans,
        ) => Ok(SerialBringUpPluginKind::Am2ZynqBm1397),
        _ => Err(SerialBringUpAdmitError::UnsupportedComposition {
            protocol,
            transport,
        }),
    }
}

/// Refine BM1362 serial plugin by board family (AM2 Zynq vs AM3 BB).
pub fn refine_bm1362_bring_up_for_board_family(
    plugin: SerialBringUpPluginKind,
    family: crate::board_desc::BoardFamily,
) -> SerialBringUpPluginKind {
    use crate::board_desc::BoardFamily;
    match (plugin, family) {
        (SerialBringUpPluginKind::Am2ZynqBm1362, BoardFamily::BeagleBone) => {
            SerialBringUpPluginKind::Am3BbBm1362
        }
        (other, _) => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_rx_interval_separates_wire_silence_from_parser_stall() {
        assert_eq!(
            classify_serial_rx_interval(100, 100, 8, 8),
            SerialRxInterval {
                wire_bytes: 0,
                framed_responses: 0,
                state: SerialRxIntervalState::Silent,
            }
        );
        assert_eq!(
            classify_serial_rx_interval(100, 112, 8, 8),
            SerialRxInterval {
                wire_bytes: 12,
                framed_responses: 0,
                state: SerialRxIntervalState::WireOnlyProgress,
            }
        );
        assert_eq!(
            classify_serial_rx_interval(100, 118, 8, 10),
            SerialRxInterval {
                wire_bytes: 18,
                framed_responses: 2,
                state: SerialRxIntervalState::FramedProgress,
            }
        );
    }

    #[test]
    fn serial_rx_interval_exposes_counter_reset() {
        assert_eq!(
            classify_serial_rx_interval(100, 4, 8, 1),
            SerialRxInterval {
                wire_bytes: 4,
                framed_responses: 1,
                state: SerialRxIntervalState::CounterReset,
            }
        );
    }

    #[test]
    fn s19k_rx_death_parser_note_is_orthogonal_to_leftover_replace() {
        assert_eq!(s19k_track1_rx_death_parser_note(None), "parser-unknown");
        assert_eq!(
            s19k_track1_rx_death_parser_note(Some(SerialRxIntervalState::Silent)),
            "host-silent"
        );
        assert_eq!(
            s19k_track1_rx_death_parser_note(Some(SerialRxIntervalState::WireOnlyProgress)),
            "wire-only-no-frame"
        );
        assert_eq!(
            s19k_track1_rx_death_parser_note(Some(SerialRxIntervalState::FramedProgress)),
            "framed-still-progress"
        );
        assert_eq!(
            SerialRxIntervalState::from_code(SerialRxIntervalState::WireOnlyProgress.as_code()),
            Some(SerialRxIntervalState::WireOnlyProgress)
        );
        assert_eq!(SerialRxIntervalState::from_code(0xFF), None);
    }

    #[test]
    fn seen_share_set_default_dedups_like_new() {
        // D1: the derived Default gave cap=0, which defeated dedup entirely
        // (the clear-at-cap check fired on every insert BEFORE the membership
        // test, so every share read as new). The manual Default routes through
        // the real constructor, so an immediate duplicate is caught.
        let mut s = SeenShareSet::default();
        assert!(s.insert(1, 42, 0), "first insert is new");
        assert!(
            !s.insert(1, 42, 0),
            "an immediate duplicate must be caught, not reported as new"
        );
    }

    #[test]
    fn history_ring_evicts_oldest() {
        let mut ring = WorkHistoryRing::new(2);
        ring.push(
            8,
            WorkHistoryEntry {
                pool_job_id: "a".into(),
                extranonce2: "00".into(),
                ntime: 1,
                version: 0x20000000,
            },
        );
        ring.push(
            8,
            WorkHistoryEntry {
                pool_job_id: "b".into(),
                extranonce2: "01".into(),
                ntime: 2,
                version: 0x20000000,
            },
        );
        ring.push(
            8,
            WorkHistoryEntry {
                pool_job_id: "c".into(),
                extranonce2: "02".into(),
                ntime: 3,
                version: 0x20000000,
            },
        );
        assert_eq!(ring.latest(8).unwrap().pool_job_id, "c");
        let ids: Vec<_> = ring
            .iter_newest_first(8)
            .map(|e| e.pool_job_id.as_str())
            .collect();
        assert_eq!(ids, vec!["c", "b"]);
    }

    #[test]
    fn history_ring_generic_accepts_engine_entry() {
        #[derive(Debug, Clone, PartialEq, Eq)]
        struct Rich {
            id: u32,
            nbits: u32,
        }
        let mut ring = WorkHistoryRing::new(2);
        ring.push(
            3,
            Rich {
                id: 1,
                nbits: 0x1d00ffff,
            },
        );
        ring.push(
            3,
            Rich {
                id: 2,
                nbits: 0x1d00fffe,
            },
        );
        assert_eq!(ring.latest(3).unwrap().id, 2);
        assert!(!ring.is_empty_slot(3));
        assert!(ring.is_empty_slot(4));
        ring.clear_all();
        assert!(ring.is_empty_slot(3));
    }

    #[test]
    fn seen_set_dedups() {
        let mut seen = SeenShareSet::new(64);
        assert!(seen.insert(8, 1, 0));
        assert!(!seen.insert(8, 1, 0));
        assert!(seen.insert(8, 2, 0));
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn seen_set_clears_when_over_cap() {
        let mut seen = SeenShareSet::new(2);
        assert!(seen.insert(1, 1, 0));
        assert!(seen.insert(1, 2, 0));
        assert_eq!(seen.len(), 2);
        // len is not yet > cap, so third insert does not clear first.
        assert!(seen.insert(1, 3, 0));
        assert_eq!(seen.len(), 3);
        // Now len > cap: next insert clears then adds one.
        assert!(seen.insert(1, 4, 0));
        assert_eq!(seen.len(), 1);
        assert!(seen.contains(1, 4, 0));
    }

    #[test]
    fn generation_seen_dedups_and_does_not_prune_on_duplicate() {
        let mut seen = GenerationSeenShareSet::new(2, 100);
        assert!(seen.insert(1, 0x1111, 0, 10));
        assert!(!seen.insert(1, 0x1111, 0, 10), "duplicate must be rejected");
        assert_eq!(seen.len(), 1, "duplicate must not prune");
        assert!(seen.insert(1, 0x2222, 1, 10));
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn generation_seen_retain_prunes_old_generations_over_cap() {
        // soft_cap=2: after 3rd insert, prune keeps gen >= current-window.
        let mut seen = GenerationSeenShareSet::new(2, 5);
        assert!(seen.insert(1, 1, 0, 1));
        assert!(seen.insert(2, 2, 0, 2));
        assert_eq!(seen.len(), 2);
        // Third insert: len becomes 3 > 2, prune with current=10, window=5 → cutoff=5.
        // gens 1 and 2 are < 5 and drop; gen 10 stays.
        assert!(seen.insert(10, 3, 0, 10));
        assert_eq!(seen.len(), 1);
        assert!(seen.contains(10, 3, 0));
        assert!(!seen.contains(1, 1, 0));
        assert!(!seen.contains(2, 2, 0));
    }

    #[test]
    fn generation_seen_serial_defaults_match_policy() {
        let s = GenerationSeenShareSet::serial_mining_defaults();
        assert_eq!(s.soft_cap(), GENERATION_SEEN_SOFT_CAP_SERIAL);
        assert_eq!(s.retain_window(), GENERATION_SEEN_RETAIN_WINDOW);
        let d = GenerationSeenShareSet::dispatcher_defaults();
        assert_eq!(d.soft_cap(), GENERATION_SEEN_SOFT_CAP_DISPATCHER);
        assert_eq!(d.retain_window(), GENERATION_SEEN_RETAIN_WINDOW);
    }

    #[test]
    fn generation_seen_clear_on_clean_jobs() {
        let mut seen = GenerationSeenShareSet::serial_mining_defaults();
        assert!(seen.insert(9, 1, 0, 9));
        seen.clear();
        assert!(seen.is_empty());
        assert!(
            seen.insert(9, 1, 0, 9),
            "after clear, same key is new again"
        );
    }

    #[test]
    fn job_cursor_steps_by_eight() {
        let mut c = AsicJobIdCursor::default_serial();
        assert_eq!(c.take_and_advance(), 0);
        assert_eq!(c.take_and_advance(), 8);
        assert_eq!(c.take_and_advance(), 16);
    }

    #[test]
    fn job_cursor_fpga_mask_wraps_at_0x7f() {
        let mut c = AsicJobIdCursor::hybrid_fpga();
        assert_eq!(c.take_and_advance(), 0);
        assert_eq!(c.take_and_advance(), 2);
        // Jump near end of 7-bit range: 0x7E + 2 = 0x80 -> masked 0x00
        let mut c = AsicJobIdCursor::with_mask(0x7E, 2, 0x7F);
        assert_eq!(c.take_and_advance(), 0x7E);
        assert_eq!(c.take_and_advance(), 0x00);
    }

    #[test]
    fn job_cursor_serial_mining_bm1398_step4() {
        let mut c = AsicJobIdCursor::serial_mining(4);
        assert_eq!(c.take_and_advance(), 0);
        assert_eq!(c.take_and_advance(), 4);
        let mut c = AsicJobIdCursor::with_mask(124, 4, 0x7F);
        assert_eq!(c.take_and_advance(), 124);
        assert_eq!(c.take_and_advance(), 0); // 128 & 0x7F = 0
    }

    #[test]
    fn job_cursor_s19k_braiins_fill_is_sequential_u8() {
        let mut c = AsicJobIdCursor::s19k_braiins_fill();
        assert_eq!(c.step(), 1);
        assert_eq!(c.mask(), 0xFF);
        assert_eq!(c.take_and_advance(), 0);
        assert_eq!(c.take_and_advance(), 1);
        assert_eq!(c.take_and_advance(), 2);
        let mut wrap = AsicJobIdCursor::with_mask(255, 1, 0xFF);
        assert_eq!(wrap.take_and_advance(), 255);
        assert_eq!(wrap.take_and_advance(), 0);
        let mut bk = SerialMiningEngineBookkeeping::s19k_braiins_fill();
        assert_eq!(bk.take_dispatch().job_id, 0);
        assert_eq!(bk.take_dispatch().job_id, 1);
        assert_ne!(
            c.step(),
            crate::s19k_bm1366_wire_b::S19K_WIRE_JOB_ID_STEP,
            "ESP/wire step-8 is not the Braiins fill cursor"
        );
        for _ in 0..40 {
            let _ = bk.take_dispatch();
        }
        assert_ne!(bk.take_dispatch().job_id, 0);
        bk.reset_s19k_braiins_fill();
        assert_eq!(bk.take_dispatch().job_id, 0);
        assert_eq!(bk.dispatch_generation(), 1);
    }

    #[test]
    fn clean_jobs_resets_bookkeeping() {
        let mut bk = SerialWorkBookkeeping::hybrid_defaults();
        bk.history.push(
            0,
            WorkHistoryEntry {
                pool_job_id: "j".into(),
                extranonce2: "ee".into(),
                ntime: 1,
                version: 0,
            },
        );
        assert!(bk.seen.insert(0, 9, 0));
        bk.on_clean_jobs();
        assert!(bk.history.latest(0).is_none());
        assert!(bk.seen.is_empty());
    }

    /// : the post-clean funnel must re-arm per clean, keep the clean
    /// count monotonic, bound dumps, and stay disarmed before the first
    /// mid-run clean (the session-start job is not a cliff risk).
    #[test]
    fn s19k_clean_funnel_rearms_per_clean_and_bounds_dumps() {
        let mut funnel = S19kCleanFunnel::default();
        assert!(!s19k_clean_funnel_armed(&funnel));
        funnel.on_clean();
        assert!(s19k_clean_funnel_armed(&funnel));
        assert_eq!(funnel.cleans, 1);
        funnel.leftover_hit = 4;
        funnel.meets = 0;
        let (hit, header, meets) = funnel.snapshot_for_post_clean_plan();
        assert_eq!((hit, header, meets), (4, 0, 0));
        funnel.on_leftover_admitted_inactive();
        assert_eq!(funnel.leftover_hit, 0);
        assert_eq!(funnel.meets, 0);
        assert_eq!(funnel.cleans, 1);
        assert_eq!(funnel.dumps_left, S19kCleanFunnel::DUMPS_PER_CLEAN);
        funnel.rxs = 7;
        funnel.correlate_fail = 3;
        funnel.misses = 4;
        funnel.leftover_hit = 2;
        funnel.unknown_miss = 2;
        for _ in 0..S19kCleanFunnel::DUMPS_PER_CLEAN {
            assert!(funnel.take_dump());
        }
        assert!(!funnel.take_dump(), "dump budget must be bounded");
        assert!(
            !funnel.take_dump_for(S19kPostCleanNonceClass::UnknownMiss),
            "UnknownMiss must not dump after the 24-slot budget"
        );
        assert!(
            funnel.take_dump_for(S19kPostCleanNonceClass::LeftoverPreClean),
            "live425 leftover_hit=6 was after the UnknownMiss budget"
        );
        assert!(
            funnel.take_dump_for(S19kPostCleanNonceClass::NewBlockShare),
            "a post-clean meet must dump even after the UnknownMiss budget"
        );
        funnel.on_clean();
        assert_eq!(funnel.cleans, 2);
        assert_eq!(funnel.rxs, 0, "per-clean stages reset on the next clean");
        assert_eq!(funnel.misses, 0);
        assert_eq!(funnel.leftover_hit, 0);
        assert_eq!(funnel.leftover_header, 0);
        assert_eq!(funnel.unknown_miss, 0);
        assert_eq!(funnel.dumps_left, S19kCleanFunnel::DUMPS_PER_CLEAN);
        assert!(funnel.frame_dump_owed);
        assert!(funnel.take_frame_dump());
        assert!(!funnel.take_frame_dump());
        assert!(s19k_should_log_full_work_frame(1, false));
        assert!(!s19k_should_log_full_work_frame(2, false));
        assert!(s19k_should_log_full_work_frame(300, true));
        assert!(!s19k_should_log_full_work_frame(0, false));
    }

    #[test]
    fn s19k_post_clean_nonce_class_prefers_leftover_when_both_meet() {
        assert_eq!(
            classify_s19k_post_clean_nonce(true, true),
            S19kPostCleanNonceClass::LeftoverPreClean
        );
        assert_eq!(
            classify_s19k_post_clean_nonce(true, false),
            S19kPostCleanNonceClass::NewBlockShare
        );
        assert_eq!(
            classify_s19k_post_clean_nonce(false, true),
            S19kPostCleanNonceClass::LeftoverPreClean
        );
        assert_eq!(
            classify_s19k_post_clean_nonce(false, false),
            S19kPostCleanNonceClass::UnknownMiss
        );
        assert!(s19k_post_clean_submit_allowed(true, false));
        assert!(!s19k_post_clean_submit_allowed(true, true));
        assert!(!s19k_post_clean_submit_allowed(false, true));
        assert!(!s19k_post_clean_submit_allowed(false, false));
    }

    ///  production pin: the serial nonce path must instrument every
    /// post-clean drop stage and dump nonce/TX pairs for offline verification.
    #[test]
    fn s19k_production_clean_funnel_is_instrumented() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/serial_mining.rs"))
            .expect("read serial_mining source");
        assert!(admit_s19k_production_clean_funnel_instrumented(&src).is_ok());
        assert!(admit_s19k_production_clean_funnel_instrumented("no funnel here").is_err());
        assert!(admit_s19k_wrap4_snapshot_preserves_wrap_retire_leftover().is_ok());
    }

    #[test]
    fn bb_depth_preset() {
        let bk: SerialWorkBookkeeping<WorkHistoryEntry> = SerialWorkBookkeeping::with_history_depth(
            crate::serial_work_policy::AM3_BB_WORK_HISTORY_PER_ID,
        );
        assert_eq!(bk.history.depth(), 128);
    }

    /// Mutation pin: hybrid dual-chain path must own pure SerialWorkBookkeeping façade.
    #[test]
    fn hybrid_am2_serial_chain_state_uses_pure_bookkeeping() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/s19j_hybrid_mining.rs"))
            .expect("read hybrid source");
        // Am2SerialChainState region must use SerialWorkBookkeeping façade (rich WorkEntry).
        let start = src
            .find("struct Am2SerialChainState")
            .expect("Am2SerialChainState");
        let body = &src[start..start + 2500];
        assert!(
            body.contains("SerialWorkBookkeeping"),
            "Am2SerialChainState must own SerialWorkBookkeeping façade"
        );
        assert!(
            body.contains("SerialWorkBookkeeping<WorkEntry>")
                || body.contains("SerialWorkBookkeeping::<WorkEntry>"),
            "Am2SerialChainState must parameterize bookkeeping over engine WorkEntry"
        );
    }

    /// Primary AM2 serial-dispatch loop (non dual-chain) must also use pure bookkeeping façade.
    #[test]
    fn hybrid_primary_serial_dispatch_uses_pure_bookkeeping() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/s19j_hybrid_mining.rs"))
            .expect("read hybrid");
        let marker = "AM2 SERIAL-WORK-DISPATCH MINING ACTIVE";
        let start = src.find(marker).expect(marker);
        let body = &src[start..start.saturating_add(3500)];
        assert!(
            body.contains("SerialWorkBookkeeping"),
            "primary serial-dispatch loop must declare SerialWorkBookkeeping near mining-active entry"
        );
        assert!(
            !body.contains("VecDeque::with_capacity(WORK_HISTORY_PER_ID)"),
            "primary serial-dispatch must not re-open-code VecDeque history rings"
        );
        assert!(
            !body.contains("let mut job_ids = AsicJobIdCursor::default_serial()"),
            "primary serial-dispatch must not open-code job_ids outside SerialWorkBookkeeping"
        );
    }

    /// Hybrid FPGA work-dispatch loop must use pure SerialWorkBookkeeping façade.
    #[test]
    fn hybrid_fpga_mining_loop_uses_pure_bookkeeping() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/s19j_hybrid_mining.rs"))
            .expect("read hybrid");
        // Prefer the FPGA banner (contains FPGA chain).
        let start = src
            .find("FPGA work dispatch + nonce collection")
            .or_else(|| src.find("=== MINING ACTIVE"))
            .expect("FPGA mining loop marker");
        let body = &src[start..start.saturating_add(4000)];
        assert!(
            body.contains("SerialWorkBookkeeping"),
            "FPGA mining loop must use SerialWorkBookkeeping façade"
        );
        assert!(
            body.contains("hybrid_fpga") || body.contains("SerialWorkBookkeeping"),
            "FPGA mining loop must construct hybrid_fpga bookkeeping preset"
        );
    }

    /// G3 gauntlet: tap mining must use pure WorkHistoryRing + hybrid_fpga
    /// job cursor (no open-coded VecDeque-of-entries work history).
    #[test]
    fn s19j_tap_mining_uses_pure_history_and_job_cursor() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/s19j_tap_mining.rs"))
            .expect("read s19j_tap_mining");
        let marker = "let mut work_builder = dcentrald_stratum::share_pipeline::WorkBuilder::new()";
        let start = src.find(marker).expect("tap work_builder init");
        // Mining loop is large; take enough chars to cover dispatch + nonce paths.
        let body: String = src[start..].chars().take(12_000).collect();
        assert!(
            body.contains("SerialWorkBookkeeping") && body.contains("hybrid_fpga"),
            "tap mining must use SerialWorkBookkeeping::hybrid_fpga façade"
        );
        assert!(
            body.contains("history.push(") || body.contains("bookkeeping.history.push"),
            "tap must push via pure ring on bookkeeping"
        );
        assert!(
            body.contains("on_clean_jobs"),
            "tap clean_jobs must use bookkeeping.on_clean_jobs (history + seen)"
        );
        assert!(
            body.contains("seen.insert"),
            "tap must dedup nonces via SeenShareSet like hybrid FPGA"
        );
        assert!(
            body.contains("iter_newest_first") || body.contains("latest("),
            "tap nonce path must use pure ring lookup"
        );
        assert!(
            !body.contains("VecDeque::with_capacity")
                && !body.contains("Vec<VecDeque")
                && !body.contains("history.pop_front()"),
            "tap must not re-open-code VecDeque work-history rings"
        );
        // Pure façade unit semantics: hybrid_fpga cursor + seen dedup.
        let mut bk = SerialWorkBookkeeping::<u32>::hybrid_fpga();
        let id0 = bk.job_ids.take_and_advance();
        assert_eq!(id0, 0);
        bk.history.push(id0, 10);
        assert!(bk.seen.insert(id0, 0xdead_beef, 0));
        assert!(!bk.seen.insert(id0, 0xdead_beef, 0));
        bk.on_clean_jobs();
        assert!(bk.history.is_empty_slot(id0));
        assert!(bk.seen.insert(id0, 0xdead_beef, 0), "clean clears seen");
        assert_eq!(bk.job_ids.mask(), 0x7F);
        assert_eq!(bk.job_ids.step(), 2);
    }

    /// serial_mining mining loop must use pure WorkHistoryRing + P1-1
    /// SerialMiningEngineBookkeeping façade (no raw generation-keyed HashSet).
    #[test]
    fn serial_mining_loop_uses_pure_history_and_job_cursor() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/serial_mining.rs"))
            .expect("read serial_mining");
        let marker = "let mut work_builder = dcentrald_stratum::share_pipeline::WorkBuilder::new()";
        let start = src.find(marker).expect("serial work_builder init");
        let body = &src[start..start.saturating_add(6500)];
        assert!(
            body.contains("WorkHistoryRing"),
            "serial_mining loop must use WorkHistoryRing"
        );
        assert!(
            body.contains("SerialMiningEngineBookkeeping"),
            "serial_mining loop must use SerialMiningEngineBookkeeping façade"
        );
        assert!(
            body.contains("let mut bookkeeping = if is_bm1366")
                && body.contains("SerialMiningEngineBookkeeping::s19k_braiins_fill")
                && body.contains("SerialMiningEngineBookkeeping::serial_mining"),
            "serial_mining must select the exact Track-1 fill or ordinary serial preset"
        );
        assert!(
            !body.contains("VecDeque::with_capacity(history_per_id)"),
            "serial_mining must not re-open-code VecDeque history rings"
        );
        assert!(
            !body.contains("HashSet<(u64, u32, u8)>"),
            "serial_mining must not re-open-code generation-keyed HashSet"
        );
        assert!(
            !body.contains("let mut dispatch_generation: u64 = 0"),
            "dispatch generation must live inside SerialMiningEngineBookkeeping"
        );
    }

    /// serial_mining + hybrid consume SerialBringUpPlugin plan phases for
    /// ChainInactive + address ladder (engine dwells remain local).
    #[test]
    fn serial_and_hybrid_engines_wire_bring_up_plugin_phases() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let serial = std::fs::read_to_string(root.join("dcentrald/src/serial_mining.rs"))
            .expect("serial_mining");
        let hybrid = std::fs::read_to_string(root.join("dcentrald/src/s19j_hybrid_mining.rs"))
            .expect("hybrid");
        assert!(
            serial.contains("plan_serial_bring_up") && serial.contains(".phases()"),
            "serial_mining must plan + phase SerialBringUpPlugin ops"
        );
        assert!(
            serial.contains("SerialBringUpPluginKind::Am2ZynqBm1362")
                && serial.contains("SerialBringUpPluginKind::AmlogicBm1368")
                && serial.contains("SerialBringUpPluginKind::AmlogicBm1370")
                && serial.contains("s19k_bm1366_native_execution_program")
                && serial.contains("native_program.pre_baud_commands"),
            "serial_mining BM1362/68/70 paths must name bring-up plugins while exact BM1366 consumes its typed cold program"
        );
        assert!(
            !serial.contains("SerialBringUpPluginKind::AmlogicBm1366"),
            "native BM1366 must not fall back to the generic bring-up plugin in serial_mining"
        );
        // BM1368/BM1370 init regions must not open-code SetAddress loops.
        let bm1368 = serial
            .find("fn init_bm1368_chain(")
            .map(|i| &serial[i..i.saturating_add(5000)])
            .expect("init_bm1368_chain");
        assert!(
            bm1368.contains("plan_serial_bring_up")
                && bm1368.contains("AmlogicBm1368")
                && bm1368.contains("address_ladder"),
            "init_bm1368_chain must use SerialBringUpPlugin address_ladder phase"
        );
        assert!(
            !bm1368.contains("send_set_address_bm1397plus((i"),
            "init_bm1368_chain must not open-code SetAddress from raw index math"
        );
        let bm1370 = serial
            .find("fn init_bm1370_chain(")
            .map(|i| &serial[i..i.saturating_add(4500)])
            .expect("init_bm1370_chain");
        assert!(
            bm1370.contains("plan_serial_bring_up")
                && bm1370.contains("AmlogicBm1370")
                && bm1370.contains("address_ladder"),
            "init_bm1370_chain must use SerialBringUpPlugin address_ladder phase"
        );
        assert!(
            !bm1370.contains("send_set_address_bm1397plus((i"),
            "init_bm1370_chain must not open-code SetAddress from raw index math"
        );
        // bm1368_chain_inactive helper must use soft_reset phase (not raw send loop).
        let inactive_helper = serial
            .find("fn bm1368_chain_inactive(")
            .map(|i| &serial[i..i.saturating_add(900)])
            .expect("bm1368_chain_inactive");
        assert!(
            inactive_helper.contains("soft_reset") && inactive_helper.contains("AmlogicBm1368"),
            "bm1368_chain_inactive must use AmlogicBm1368 soft_reset phase"
        );
        assert!(
            hybrid.contains("plan_serial_bring_up") && hybrid.contains(".phases()"),
            "hybrid must plan + phase SerialBringUpPlugin ops"
        );
        assert!(
            hybrid.contains("SerialBringUpPluginKind::Am2ZynqBm1362"),
            "hybrid must use Am2ZynqBm1362 bring-up plugin"
        );
    }

    #[test]
    fn amlogic_bm1368_and_bm1370_bring_up_plans_are_admitted() {
        use crate::board_desc::ChainTransportKind;
        use crate::chain_transport::TransportOp;

        for (plugin, inactive_n) in [
            (SerialBringUpPluginKind::AmlogicBm1368, 3u8),
            (SerialBringUpPluginKind::AmlogicBm1370, 1u8),
        ] {
            let plan = plan_serial_bring_up(
                plugin,
                ChainTransportKind::Serial,
                &SerialBringUpPlanParams {
                    chip_count: 65,
                    frequency_mhz: 0,
                    chain_inactive_count: inactive_n,
                    inactive_dwell_ms: 0,
                    post_enum_delay_ms: 0,
                },
            )
            .unwrap_or_else(|e| panic!("{plugin:?} plan: {e}"));
            let phases = plan.phases();
            assert_eq!(
                phases
                    .soft_reset
                    .iter()
                    .filter(|o| matches!(o, TransportOp::SendChainInactiveBm1397Plus))
                    .count(),
                inactive_n as usize,
                "{plugin:?} soft_reset inactive count"
            );
            // 256/65 = 3 → 65 SetAddress ops
            assert_eq!(phases.address_ladder.len(), 65, "{plugin:?} ladder len");
            assert_eq!(
                phases.address_ladder.first(),
                Some(&TransportOp::SendSetAddressBm1397Plus { addr: 0 })
            );
            assert_eq!(
                phases.address_ladder.get(1),
                Some(&TransportOp::SendSetAddressBm1397Plus { addr: 3 })
            );
        }
    }

    #[test]
    fn amlogic_bm1366_bring_up_uses_aml_interval_2_not_public_floor_3() {
        use crate::board_desc::ChainTransportKind;
        use crate::chain_transport::TransportOp;

        let plan = plan_serial_bring_up(
            SerialBringUpPluginKind::AmlogicBm1366,
            ChainTransportKind::Serial,
            &SerialBringUpPlanParams {
                chip_count: 77,
                frequency_mhz: 0,
                chain_inactive_count: 1,
                inactive_dwell_ms: 0,
                post_enum_delay_ms: 0,
            },
        )
        .expect("s19k plan");
        let addrs: Vec<u8> = plan
            .ops
            .iter()
            .filter_map(|o| match o {
                TransportOp::SendSetAddressBm1397Plus { addr } => Some(*addr),
                _ => None,
            })
            .collect();
        assert_eq!(addrs.len(), 77);
        assert_eq!(addrs[0], 0);
        assert_eq!(addrs[1], 2);
        assert_ne!(addrs[1], 3);
        assert_eq!(addrs[76], 152);
        assert_eq!(crate::s19k_bm1366_wire_b::S19K_AML_ADDR_INTERVAL, 2);
        assert_eq!(crate::s19k_bm1366_wire_b::S19K_PUBLIC_ADDR_INTERVAL, 3);
    }

    #[test]
    fn serial_mining_engine_bookkeeping_take_dispatch_and_dedup() {
        let mut eng = SerialMiningEngineBookkeeping::serial_mining(8);
        let t0 = eng.take_dispatch();
        assert_eq!(t0.job_id, 0);
        assert_eq!(t0.generation, 0);
        let t1 = eng.take_dispatch();
        assert_eq!(t1.job_id, 8);
        assert_eq!(t1.generation, 1);
        assert!(eng.admit_share(0, 0xAABB_CCDD, 0));
        assert!(!eng.admit_share(0, 0xAABB_CCDD, 0));
        eng.on_clean_jobs();
        assert!(
            eng.admit_share(0, 0xAABB_CCDD, 0),
            "clean jobs clears dedup"
        );
        assert_eq!(eng.dispatch_generation(), 2);
        assert_eq!(serial_work_min_interval_ms(), 20);
    }

    #[test]
    fn work_dispatcher_bookkeeping_take_generation_and_admit() {
        let mut eng = SerialMiningEngineBookkeeping::work_dispatcher();
        assert_eq!(eng.take_generation(), 0);
        assert_eq!(eng.take_generation(), 1);
        assert_eq!(eng.dispatch_generation(), 2);
        // Generation-only path does not advance the unused job-id cursor.
        assert_eq!(eng.job_ids.current(), 0);
        assert!(eng.admit_share(0, 0x1122_3344, 0));
        assert!(!eng.admit_share(0, 0x1122_3344, 0));
        // Soft-cap path: midstate collapse (idx 0) is still generation-keyed.
        assert!(eng.admit_share(1, 0x1122_3344, 0));
        assert_eq!(eng.seen.soft_cap(), GENERATION_SEEN_SOFT_CAP_DISPATCHER);
    }

    #[test]
    fn serial_bring_up_plugin_admit_matrix() {
        use crate::board_desc::{AsicProtocolIdentity, BoardFamily, ChainTransportKind};

        assert_eq!(
            admit_serial_bring_up_plugin(
                AsicProtocolIdentity::Bm1362,
                ChainTransportKind::ZynqHybrid
            )
            .unwrap(),
            SerialBringUpPluginKind::Am2ZynqBm1362
        );
        assert_eq!(
            refine_bm1362_bring_up_for_board_family(
                SerialBringUpPluginKind::Am2ZynqBm1362,
                BoardFamily::BeagleBone
            ),
            SerialBringUpPluginKind::Am3BbBm1362
        );
        assert_eq!(
            admit_serial_bring_up_plugin(AsicProtocolIdentity::Bm1366, ChainTransportKind::Serial)
                .unwrap(),
            SerialBringUpPluginKind::AmlogicBm1366
        );
        assert_eq!(
            admit_serial_bring_up_plugin(AsicProtocolIdentity::Bm1368, ChainTransportKind::Serial)
                .unwrap()
                .as_str(),
            "amlogic_bm1368"
        );
        assert!(matches!(
            admit_serial_bring_up_plugin(AsicProtocolIdentity::Bm1387, ChainTransportKind::FpgaUio),
            Err(SerialBringUpAdmitError::UnsupportedComposition { .. })
        ));
        assert!(matches!(
            admit_serial_bring_up_plugin(AsicProtocolIdentity::Bm1362, ChainTransportKind::None),
            Err(SerialBringUpAdmitError::ManagementOnlyTransport)
        ));
        // BoardDesc rows that are mining-serial must admit a plugin.
        for desc in crate::board_desc::BoardDesc::all_registered() {
            if matches!(
                desc.work_engine,
                crate::board_desc::WorkEngineKind::SerialWork
            ) {
                let plugin = admit_serial_bring_up_plugin(desc.asic_protocol, desc.chain_transport)
                    .unwrap_or_else(|e| {
                        panic!(
                            "{} SerialWork must admit bring-up plugin: {e}",
                            desc.board_target
                        )
                    });
                let refined = refine_bm1362_bring_up_for_board_family(plugin, desc.family);
                if matches!(desc.family, BoardFamily::BeagleBone)
                    && matches!(desc.asic_protocol, AsicProtocolIdentity::Bm1362)
                {
                    assert_eq!(refined, SerialBringUpPluginKind::Am3BbBm1362);
                }
            }
        }
    }

    #[test]
    fn serial_bring_up_plugin_plans_inactive_enum_and_full_population_ladder() {
        use crate::board_desc::ChainTransportKind;
        use crate::chain_transport::TransportOp;

        let params = SerialBringUpPlanParams {
            chip_count: 126,
            frequency_mhz: 400,
            chain_inactive_count: 3,
            inactive_dwell_ms: 300,
            post_enum_delay_ms: 100,
        };
        let plan = SerialBringUpPluginKind::Am2ZynqBm1362
            .plan(ChainTransportKind::ZynqHybrid, &params)
            .expect("plan");
        assert_eq!(plan.plugin, SerialBringUpPluginKind::Am2ZynqBm1362);
        assert!(plan.frequency_program_deferred, "PLL must stay deferred");

        let inactive = plan
            .ops
            .iter()
            .filter(|o| matches!(o, TransportOp::SendChainInactiveBm1397Plus))
            .count();
        assert_eq!(inactive, 3);
        assert!(plan
            .ops
            .iter()
            .any(|o| matches!(o, TransportOp::SendGetAddressBm1397Plus)));
        let set_addrs: Vec<u8> = plan
            .ops
            .iter()
            .filter_map(|o| match o {
                TransportOp::SendSetAddressBm1397Plus { addr } => Some(*addr),
                _ => None,
            })
            .collect();
        // 256/126 = 2 → 0, 2, 4, … for 126 chips
        assert_eq!(set_addrs.len(), 126);
        assert_eq!(set_addrs[0], 0);
        assert_eq!(set_addrs[1], 2);
        assert_eq!(set_addrs[125], 250);
        // No invented PLL register writes.
        assert!(!plan.ops.iter().any(|o| matches!(
            o,
            TransportOp::SendWriteRegBroadcastBm1397Plus { .. }
                | TransportOp::SendWriteRegBm1397Plus { .. }
        )));
    }

    #[test]
    fn serial_bring_up_plugin_executes_on_recording_transport() {
        use crate::board_desc::ChainTransportKind;
        use crate::chain_transport::RecordingChainTransport;

        let params = SerialBringUpPlanParams::with_chip_count(4);
        let mut rec = RecordingChainTransport::new(ChainTransportKind::Serial, "bringup-test");
        let plan = SerialBringUpPluginKind::AmlogicBm1366
            .execute(&mut rec, &params)
            .expect("execute");
        assert_eq!(rec.recorded, plan.ops);
        assert!(!plan.ops.is_empty());
        // Enumerate-only path when chip_count=0 still produces inactive+get.
        let mut rec2 = RecordingChainTransport::new(ChainTransportKind::Serial, "enum-only");
        let plan2 = SerialBringUpPluginKind::AmlogicBm1366
            .execute(&mut rec2, &SerialBringUpPlanParams::default())
            .expect("enum-only");
        assert!(plan2.ops.iter().any(|o| matches!(
            o,
            crate::chain_transport::TransportOp::SendGetAddressBm1397Plus
        )));
        assert!(!plan2.ops.iter().any(|o| matches!(
            o,
            crate::chain_transport::TransportOp::SendSetAddressBm1397Plus { .. }
        )));
    }

    #[test]
    fn serial_bring_up_refuses_management_only_and_wrong_transport_kind() {
        use crate::board_desc::ChainTransportKind;
        use crate::chain_transport::RecordingChainTransport;

        let err = plan_serial_bring_up(
            SerialBringUpPluginKind::Am2ZynqBm1362,
            ChainTransportKind::None,
            &SerialBringUpPlanParams::with_chip_count(1),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SerialBringUpPlanError::Admit(SerialBringUpAdmitError::ManagementOnlyTransport)
                | SerialBringUpPlanError::ProtocolTransport(_)
        ));

        // Plan for Serial, execute on mismatched ZynqHybrid recorder → fail closed.
        let plan = plan_serial_bring_up(
            SerialBringUpPluginKind::Am2ZynqBm1362,
            ChainTransportKind::Serial,
            &SerialBringUpPlanParams::with_chip_count(1),
        )
        .expect("plan serial");
        let mut wrong = RecordingChainTransport::new(ChainTransportKind::ZynqHybrid, "wrong-kind");
        let err = execute_serial_bring_up_plan(&mut wrong, &plan).unwrap_err();
        assert!(matches!(
            err,
            SerialBringUpPlanError::TransportKindMismatch { .. }
        ));
    }

    #[test]
    fn serial_bring_up_board_desc_rows_plan_when_serial_work() {
        use crate::board_desc::WorkEngineKind;

        for desc in crate::board_desc::BoardDesc::all_registered() {
            if !matches!(desc.work_engine, WorkEngineKind::SerialWork) {
                continue;
            }
            // RuntimeDiscovered / management boards should not claim SerialWork
            // with active plugins; if they do, plan must still be honest.
            let params = SerialBringUpPlanParams::with_chip_count(2);
            match plan_serial_bring_up_for_board(desc, &params) {
                Ok(plan) => {
                    assert_eq!(plan.admission.protocol(), plan.plugin.asic_protocol());
                    assert!(!plan.ops.is_empty(), "{} plan empty", desc.board_target);
                }
                Err(e) => panic!(
                    "{} SerialWork board must plan bring-up: {e}",
                    desc.board_target
                ),
            }
        }
    }

    #[test]
    fn serial_bring_up_plan_phases_split_inactive_enum_and_ladder() {
        use crate::board_desc::ChainTransportKind;
        use crate::chain_transport::TransportOp;

        let plan = plan_serial_bring_up(
            SerialBringUpPluginKind::Am2ZynqBm1362,
            ChainTransportKind::Serial,
            &SerialBringUpPlanParams {
                chip_count: 4,
                frequency_mhz: 0,
                chain_inactive_count: 3,
                inactive_dwell_ms: 300,
                post_enum_delay_ms: 100,
            },
        )
        .expect("plan");
        let phases = plan.phases();
        assert_eq!(
            phases
                .soft_reset
                .iter()
                .filter(|o| matches!(o, TransportOp::SendChainInactiveBm1397Plus))
                .count(),
            3
        );
        assert!(phases
            .soft_reset
            .iter()
            .any(|o| matches!(o, TransportOp::DelayMs { ms: 300 })));
        assert_eq!(
            phases.enumerate,
            vec![
                TransportOp::SendGetAddressBm1397Plus,
                TransportOp::DelayMs { ms: 100 },
            ]
        );
        assert_eq!(phases.address_ladder.len(), 4);
        assert!(phases.other.is_empty());
        // Concatenating phases (ignoring empty other) rebuilds command narrative
        // order: inactive → enum → ladder (dwells included).
        let mut rebuilt = phases.soft_reset.clone();
        rebuilt.extend(phases.enumerate.clone());
        rebuilt.extend(phases.address_ladder.clone());
        assert_eq!(rebuilt, plan.ops);
    }

    #[test]
    fn am2_and_bb_plugins_share_bm1362_protocol_but_distinct_identity() {
        assert_eq!(
            SerialBringUpPluginKind::Am2ZynqBm1362.asic_protocol(),
            SerialBringUpPluginKind::Am3BbBm1362.asic_protocol()
        );
        assert_ne!(
            SerialBringUpPluginKind::Am2ZynqBm1362.as_str(),
            SerialBringUpPluginKind::Am3BbBm1362.as_str()
        );
        let p = SerialBringUpPlanParams::with_chip_count(3);
        let a = plan_serial_bring_up(
            SerialBringUpPluginKind::Am2ZynqBm1362,
            crate::board_desc::ChainTransportKind::Serial,
            &p,
        )
        .unwrap();
        let b = plan_serial_bring_up(
            SerialBringUpPluginKind::Am3BbBm1362,
            crate::board_desc::ChainTransportKind::Serial,
            &p,
        )
        .unwrap();
        // Same pure transport narrative offline; plugin identity differs.
        assert_eq!(a.ops, b.ops);
        assert_ne!(a.plugin, b.plugin);
    }

    /// FPGA work_dispatcher must own SerialMiningEngineBookkeeping façade
    /// (generation-keyed SSOT; no free-floating serial/generation locals).
    #[test]
    fn work_dispatcher_uses_generation_seen_share_set() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/work_dispatcher.rs"))
            .expect("read work_dispatcher");
        assert!(
            src.contains("SerialMiningEngineBookkeeping"),
            "work_dispatcher must use SerialMiningEngineBookkeeping façade"
        );
        assert!(
            src.contains("SerialMiningEngineBookkeeping::work_dispatcher"),
            "work_dispatcher must construct via work_dispatcher() preset"
        );
        assert!(
            !src.contains("HashSet<(u64, u32, u8)>"),
            "work_dispatcher must not re-open-code generation-keyed HashSet"
        );
        assert!(
            !src.contains("let mut next_dispatch_serial: u64 = 0"),
            "dispatch generation must live inside SerialMiningEngineBookkeeping"
        );
        assert!(
            !src.contains("GenerationSeenShareSet::dispatcher_defaults()"),
            "seen set must live inside SerialMiningEngineBookkeeping, not open-coded"
        );
    }

    /// G14/G15: stock mining must use pure WorkHistoryRing depth=1 keyed from
    /// FPGA `dispatch_work` REG_JOB_ID return (low byte). No separate CPU
    /// AsicJobIdCursor for history; no open-coded Vec table; no SeenShareSet.
    #[test]
    fn stock_mining_uses_pure_history_ring_depth_one() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/stock_mining.rs"))
            .expect("read stock_mining");
        // Mining loop markers around work tracking.
        assert!(
            src.contains("WorkHistoryRing") && src.contains("WorkHistoryRing::new(1)"),
            "stock mining must use WorkHistoryRing depth=1"
        );
        assert!(
            src.contains("work_history.clear_all()"),
            "stock clean_jobs must clear pure history ring"
        );
        assert!(
            src.contains("work_history.latest(") || src.contains("work_history.latest"),
            "stock nonce path must lookup via pure ring latest()"
        );
        assert!(
            src.contains("work_history.push("),
            "stock dispatch must push via pure ring"
        );
        assert!(
            !src.contains("vec![None; 256]")
                && !src.contains("Vec<Option<StockWorkEntry>>")
                && !src.contains("let mut work_table"),
            "stock must not re-open-code work_table Vec<Option<[256]>>"
        );
        assert!(
            !src.contains("let mut work_id_counter: u8"),
            "stock must not open-code bare work_id_counter"
        );
        // Anti-goal: do not invent share-dedup on stock path in this wave.
        let mining_start = src
            .find("let mut work_builder")
            .expect("stock work_builder init");
        let mining_body: String = src[mining_start..].chars().take(25_000).collect();
        assert!(
            !mining_body.contains("SeenShareSet") && !mining_body.contains("SerialWorkBookkeeping"),
            "G14 stock history strangler must not invent SeenShareSet/bookkeeping façade"
        );
        // G15: correlation spine is FPGA REG_JOB_ID return, not a dual CPU cursor.
        assert!(
            mining_body.contains("dispatch_work(")
                && mining_body.contains("fpga_job_id")
                && mining_body.contains("(fpga_job_id & 0xFF) as u8"),
            "stock must key history from dispatch_work REG_JOB_ID low byte"
        );
        assert!(
            !mining_body.contains("let _fpga_job_id"),
            "stock must not discard FPGA job id with _fpga_job_id (G15 dual-id residual)"
        );
        assert!(
            !mining_body.contains("AsicJobIdCursor"),
            "stock history must not use a separate AsicJobIdCursor alongside FPGA REG_JOB_ID"
        );
        // Pure unit: depth-1 overwrite + clear (slot key independent of cursor).
        let mut ring = WorkHistoryRing::new(1);
        let id0 = 0u8;
        ring.push(
            id0,
            WorkHistoryEntry {
                pool_job_id: "a".into(),
                extranonce2: "00".into(),
                ntime: 1,
                version: 0,
            },
        );
        ring.push(
            id0,
            WorkHistoryEntry {
                pool_job_id: "b".into(),
                extranonce2: "01".into(),
                ntime: 2,
                version: 0,
            },
        );
        assert_eq!(ring.latest(id0).unwrap().pool_job_id, "b");
        assert_eq!(ring.slot_len(id0), 1, "depth-1 keeps one entry only");
        ring.clear_all();
        assert!(ring.latest(id0).is_none());
    }

    /// G15 pure: stock history keys follow FPGA post-inc REG_JOB_ID low byte
    /// (dispatch returns 1,2,3…; nonce EXT work field low byte looks up same slots).
    /// Models StockFpgaWorkEngine::dispatch_work job_id wrapping_add(1) spine.
    #[test]
    fn stock_history_keys_match_fpga_reg_job_id_post_inc_spine() {
        // HAL contract pin: dispatch_work post-inc then write_reg(REG_JOB_ID) then return.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let hal = std::fs::read_to_string(root.join("dcentrald-hal/src/stock_fpga_work.rs"))
            .expect("read stock_fpga_work");
        let dispatch = {
            let start = hal.find("pub fn dispatch_work(").expect("dispatch_work");
            let end = hal[start..]
                .find("pub fn dispatch_work_asicboost")
                .map(|offset| start + offset)
                .expect("dispatch_work_asicboost");
            &hal[start..end]
        };
        assert!(
            dispatch.contains("let next_job_id = self.job_id.wrapping_add(1)")
                && dispatch.contains("write_reg(REG_JOB_ID, next_job_id)")
                && dispatch.contains("self.job_id = next_job_id"),
            "HAL dispatch_work must derive, publish, then retain the next REG_JOB_ID"
        );
        // Return value is bare `self.job_id` (not a different counter).
        let return_idx = dispatch
            .rfind("self.job_id")
            .expect("dispatch_work must mention self.job_id as return");
        let after_return = dispatch[return_idx..].chars().take(40).collect::<String>();
        assert!(
            after_return.contains("self.job_id")
                && (after_return.contains('}') || after_return.lines().next().is_some()),
            "HAL dispatch_work must return self.job_id (post-inc spine)"
        );
        // Ordering pin: wrapping_add before write_reg(REG_JOB_ID).
        let add_pos = dispatch
            .find("let next_job_id = self.job_id.wrapping_add(1)")
            .expect("post-inc");
        let write_pos = dispatch
            .find("write_reg(REG_JOB_ID, next_job_id)")
            .expect("REG_JOB_ID write");
        assert!(
            add_pos < write_pos,
            "HAL must post-inc before writing REG_JOB_ID (not pre-write)"
        );
        // Stock mining pin: nonce EXT >> 8 extract (not only push-side mask).
        let stock = std::fs::read_to_string(root.join("dcentrald/src/stock_mining.rs"))
            .expect("read stock_mining");
        let mining_start = stock
            .find("let mut work_builder")
            .expect("stock work_builder");
        let mining_body: String = stock[mining_start..].chars().take(25_000).collect();
        assert!(
            mining_body.contains("((ext >> 8) & 0xFFFF)")
                || mining_body.contains("((ext >> 8) & 0xffff)"),
            "stock nonce path must extract work field from RETURN_NONCE_EXT >> 8"
        );

        // Non-tautological vector: push key from full REG_JOB_ID low byte;
        // lookup key from bmminer-style EXT word with work id in bits [23:8].
        // e.g. REG_JOB_ID=0x1AB → push slot 0xAB; EXT packs work id at >>8.
        let mut history: WorkHistoryRing<WorkHistoryEntry> = WorkHistoryRing::new(1);
        let vectors: &[(u32, &str)] = &[
            (1, "job-1"),
            (2, "job-2"),
            (0x1AB, "job-1ab"),
            (0x100, "job-100"),
        ];
        for &(reg_job_id, pool_id) in vectors {
            let push_key = (reg_job_id & 0xFF) as u8;
            history.push(
                push_key,
                WorkHistoryEntry {
                    pool_job_id: pool_id.into(),
                    extranonce2: "00".into(),
                    ntime: reg_job_id,
                    version: 0,
                },
            );
            // Model RETURN_NONCE_EXT: bits [23:8] = extended_work_id (REG_JOB_ID low 16).
            let ext = ((reg_job_id & 0xFFFF) as u32) << 8;
            let ext_work_id = ((ext >> 8) & 0xFFFF) as u16;
            let lookup_key = (ext_work_id & 0xFF) as u8;
            assert_eq!(
                lookup_key, push_key,
                "push low-byte and EXT>>8 low-byte must match for REG_JOB_ID={reg_job_id:#x}"
            );
            assert_eq!(history.latest(lookup_key).unwrap().pool_job_id, pool_id);
        }
        // Off-by-one residual G15 closed: post-inc first return is 1, not CPU 0.
        assert!(history.latest(1).is_some());
        assert!(
            history.latest(0xAB).is_some(),
            "multi-byte REG_JOB_ID 0x1AB must key slot 0xAB"
        );
        assert_eq!(history.latest(0).unwrap().pool_job_id, "job-100");
    }

    /// G13: am3_bb mining loop owns pure SerialWorkBookkeeping façade (not three locals).
    #[test]
    fn am3_bb_mining_loop_uses_seen_share_set() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let src = std::fs::read_to_string(root.join("dcentrald/src/am3_bb_mining.rs"))
            .expect("read am3_bb_mining");
        let marker = "=== am3-bb MINING ACTIVE";
        let start = src.find(marker).expect(marker);
        // Mining loop is large — cover dispatch + both nonce paths (inserts ~20k+).
        let body: String = src[start..].chars().take(30_000).collect();
        assert!(
            body.contains("SerialWorkBookkeeping")
                && (body.contains("SerialWorkBookkeeping::<DispatchedWork>")
                    || body.contains("SerialWorkBookkeeping<DispatchedWork>")),
            "am3_bb mining-active region must own SerialWorkBookkeeping façade over DispatchedWork"
        );
        assert!(
            body.contains("with_depth_and_cursor"),
            "am3_bb must assemble façade via with_depth_and_cursor (depth + codec cursor)"
        );
        assert!(
            body.contains("on_clean_jobs"),
            "am3_bb clean_jobs must use bookkeeping.on_clean_jobs (history + seen atomic)"
        );
        assert!(
            !body.contains("let mut work_history")
                && !body.contains("let mut seen_shares")
                && !body.contains("let mut job_ids = match"),
            "am3_bb must not open-code three separate bookkeeping locals"
        );
        assert!(
            !body.contains("seen_shares.clear()") && !body.contains("work_history.clear_all()"),
            "am3_bb must not dual-clear seen/history outside on_clean_jobs"
        );
        assert!(
            !body.contains("HashSet<(u8, u32, u16)>"),
            "am3_bb must not re-open-code job-id keyed HashSet for share dedup"
        );
        assert!(
            !body.contains("SEEN_SHARES_SOFT_CAP"),
            "am3_bb must use DEFAULT_SEEN_SHARES_CAP via SeenShareSet, not a local soft-cap constant"
        );
        assert!(
            !body.contains("work_by_id"),
            "am3_bb must not re-open-code work_by_id VecDeque history table"
        );
        // Both nonce paths (serial + asic86) must call typed insert on façade.seen.
        //
        // Counted on a WHITESPACE-STRIPPED copy: `cargo fmt` breaks the longer of
        // the two call sites across lines (`bookkeeping\n.seen\n.insert(...)`), so
        // counting the contiguous literal silently dropped it to 1 and failed a
        // contract whose invariant was actually intact. Never count raw source
        // text for a call-site contract — reformatting is not a semantic change.
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let insert_calls = compact.matches("bookkeeping.seen.insert(").count();
        assert!(
            insert_calls >= 2,
            "expected ≥2 bookkeeping.seen.insert call sites (serial + asic86), found {insert_calls}"
        );
        // Pure unit: depth + cursor assembly + atomic clean.
        let mut bk = SerialWorkBookkeeping::<u32>::with_depth_and_cursor(
            crate::serial_work_policy::AM3_BB_WORK_HISTORY_PER_ID,
            AsicJobIdCursor::serial_mining(24),
        );
        assert_eq!(bk.history.depth(), 128);
        assert_eq!(bk.job_ids.take_and_advance(), 0);
        assert_eq!(bk.job_ids.take_and_advance(), 24);
        bk.history.push(0, 1u32);
        assert!(bk.seen.insert(0, 1, 0));
        bk.on_clean_jobs();
        assert!(bk.history.latest(0).is_none());
        assert!(bk.seen.is_empty());
        assert!(
            bk.seen.insert(0, 1, 0),
            "after clean, same key admitted again"
        );
    }

    #[test]
    fn history_ring_slot_len_tracks_pushes() {
        let mut ring = WorkHistoryRing::new(3);
        assert_eq!(ring.slot_len(1), 0);
        ring.push(
            1,
            WorkHistoryEntry {
                pool_job_id: "a".into(),
                extranonce2: "00".into(),
                ntime: 1,
                version: 0,
            },
        );
        ring.push(
            1,
            WorkHistoryEntry {
                pool_job_id: "b".into(),
                extranonce2: "01".into(),
                ntime: 2,
                version: 0,
            },
        );
        assert_eq!(ring.slot_len(1), 2);
        assert_eq!(ring.slot_len(2), 0);
    }
}
