//! Pure, dependency-free HAL write-protect policy for the TPS546 power IC
//! (XPSAFE-2, cross-pollinated from DCENT_OS).
//!
//! ## Why this exists
//!
//! DCENT_OS bakes a HAL-level write denylist into its `I2cBus` (`set_write_denylist`)
//! so a code bug cannot corrupt the hashboard EEPROM calibration store at I2C
//! addresses `0x50..=0x57` (the `.74` hb2 EEPROM corruption incident, 2026-04-29).
//! BitAxe has **no analogous persistent I2C calibration store**: board identity /
//! tuning lives in the ESP32's internal NVS flash (not reachable by any I2C
//! peripheral write), the DS4432U DAC registers are volatile current-sink codes,
//! and the firmware never issues the TPS546 `STORE_USER_ALL` NVM-commit command.
//!
//! The one genuinely-corruptible-by-a-buggy-write surface on BitAxe is the
//! **TPS546 protection-limit register set** — the OV / OC / OT / UV fault
//! thresholds that are the regulator's last-line *hardware* protection for the
//! ASIC rail. Those registers are volatile, but a buggy autotuner / MCP / REST
//! path (the raw `I2cBus::write*` primitives are public and reachable) landing a
//! stray write on one of them could *raise* a fault threshold above a safe value
//! and silently defeat the regulator's own protection while the chips run.
//!
//! This module is the SINGLE SOURCE OF TRUTH for which TPS546 registers belong
//! to that protected set and for the predicate that decides whether a given
//! `(addr, register)` write must be refused. It is deliberately NOT gated to the
//! ESP-IDF target (like `safety` / `cml_escalation` / `temp_decode`): every item
//! is a `const fn` / `const` over plain integers with no `esp-idf-hal` / `log` /
//! heap dependency, so the policy host-compiles and its truth table is unit-tested
//! on the host (`cargo test -p dcentaxe-core` / `-p dcentaxe-hal`). The espidf-only
//! `i2c::I2cBus` write path consults `is_protected_register` so a driver and the
//! guard can never disagree about which register is protected.
//!
//! ## Default-preserving (XPSAFE-2 triage: land-gated-default-off)
//!
//! The guard is **disarmed by default** (`GuardState::default().armed == false`).
//! On a field-proven board nothing changes: `is_write_blocked` returns `false`
//! for every register until the platform explicitly arms the guard AND latches it
//! at the end of `PowerManager` init (after the legitimate `configure_limits`
//! pass has written the thresholds). Reads are NEVER affected — only writes to the
//! protected set, and only once armed+latched. Legitimate re-init writes (a fresh
//! `PowerManager::new`, which constructs a new bus state) are therefore never
//! blocked; only post-init stray writes are.

/// Primary TPS546 PMBus I2C address (matches `power::TPS546_ADDR`). Every board
/// with a TPS546 has one at this address; the guard and the multi-regulator
/// policy below both treat it as the first member of the active address set.
pub const TPS546_ADDR: u8 = 0x24;

// ===========================================================================
// Multi-regulator address policy (Lucky Miner LV08 — SPEC §4, 2026-07-27)
// ===========================================================================
//
// The Lucky Miner LV08 carries THREE paralleled single-phase TPS546 regulators
// on ONE ~1.2 V rail feeding nine BM1366 dies (~39 A at ~140 W). Vendor ground
// truth (LVXX `TPS546.c:35`): `TPS546_I2C_ADDR[3] = {0x24, 0x7F, 0x14}`
// (U2, U1, U3 — the array order is the vendor's init/broadcast order and is
// preserved here). Every other TPS546 board — including Lucky LV06/LV07 — has
// exactly one regulator at 0x24.
//
// This is NOT the GT `stack_config` multi-phase MFR path: the GT is a
// current-sharing phase stack behind one PMBus target; the LV08 is three
// independent regulators that must each be initialized, limit-configured,
// broadcast the same setpoint, and fault-checked individually.

/// The ordered TPS546 address set for the Lucky Miner LV08 (vendor order).
pub const LUCKY_LV08_TPS546_ADDRS: &[u8] = &[0x24, 0x7F, 0x14];

/// The TPS546 address set for every non-LV08 board (single regulator at 0x24).
pub const SINGLE_TPS546_ADDR_SET: &[u8] = &[TPS546_ADDR];

/// The two LV08-only secondary regulator addresses, in vendor order. `0x7F` is
/// an I2C spec-reserved address — safe to (read-only) probe, but probing must
/// be gated to suspected-Lucky hardware only (SPEC §4 caution).
pub const LUCKY_LV08_SECONDARY_TPS546_ADDRS: &[u8] = &[0x7F, 0x14];

/// Select the active TPS546 address set. The boolean seam is deliberate: this
/// module is dependency-free by charter, so the `BitAxeModel::LuckyLv08 → true`
/// mapping lives at the (espidf-gated) call site in `power::PowerManager::new`.
/// `true` is passed for the Lucky LV08 ONLY; every other board — including
/// Lucky LV06/LV07 — must pass `false`.
pub const fn tps546_addr_set(lv08_triple_regulator: bool) -> &'static [u8] {
    if lv08_triple_regulator {
        LUCKY_LV08_TPS546_ADDRS
    } else {
        SINGLE_TPS546_ADDR_SET
    }
}

/// Addresses the fault-limit write guard covers: the full LV08 superset.
///
/// Guarding `0x7F`/`0x14` unconditionally (on every board, not just LV08) is
/// deliberately conservative and behavior-preserving: no shipping BitAxe-class
/// board has ANY device at those addresses, so on non-LV08 boards there are no
/// legitimate writes there for the guard to interfere with — while on LV08 all
/// three regulators get identical protection with no runtime board state
/// threaded into this pure module.
pub const GUARDED_TPS546_ADDRS: &[u8] = LUCKY_LV08_TPS546_ADDRS;

/// Returns `true` if `addr` is a TPS546 address covered by the fault-limit
/// write guard (the primary 0x24 plus the LV08 secondaries 0x7F/0x14).
pub const fn is_guarded_tps546_addr(addr: u8) -> bool {
    let mut i = 0;
    while i < GUARDED_TPS546_ADDRS.len() {
        if GUARDED_TPS546_ADDRS[i] == addr {
            return true;
        }
        i += 1;
    }
    false
}

// ===========================================================================
// Multi-regulator telemetry aggregation (pure, host-tested)
// ===========================================================================
//
// Aggregation contract (vendor ground truth, LVXX `power.c:24-37` /
// `vcore.c:197-207`): power and current are SUMMED across regulators; vout,
// vin, and temperature are the MAX across regulators. The board-level power
// offset (18 W for the whole Lucky family, LVXX `power.c:24-37`) is added
// exactly ONCE to the summed power — never per regulator.
//
// Dead-regulator visibility (SPEC §4 caution): the espidf caller propagates a
// per-regulator I2C read error as `Err` BEFORE these functions ever run, so a
// dead regulator can never be silently averaged away. As defense-in-depth these
// functions additionally POISON on NaN inputs: any NaN reading makes the
// aggregate NaN ("unavailable" in the HALPWR-2 telemetry contract) instead of
// being skipped by a max/sum. Do NOT "fix" that by filtering NaN out.

/// Sum per-regulator output power (`Σ vout_i × iout_i`) and add the board
/// offset once. NaN in any pair poisons the result (visible, not masked).
pub fn sum_regulator_power_w(vout_iout_v_a: &[(f32, f32)], board_offset_w: f32) -> f32 {
    let mut total = board_offset_w;
    for &(vout_v, iout_a) in vout_iout_v_a {
        total += vout_v * iout_a;
    }
    total
}

/// Sum per-regulator output current. NaN poisons the result.
pub fn sum_regulator_current_a(iout_a: &[f32]) -> f32 {
    let mut total = 0.0f32;
    for &i in iout_a {
        total += i;
    }
    total
}

/// Max across per-regulator readings (vout / vin / temperature aggregation).
///
/// Returns `None` for an empty set. Returns `Some(NaN)` if ANY reading is NaN —
/// a plain `f32::max` fold would silently prefer the non-NaN operand and let a
/// dead regulator's reading vanish from the aggregate, which is exactly the
/// masking failure SPEC §4 forbids.
pub fn max_regulator_reading(readings: &[f32]) -> Option<f32> {
    if readings.is_empty() {
        return None;
    }
    let mut max = f32::NEG_INFINITY;
    for &r in readings {
        if r.is_nan() {
            return Some(f32::NAN);
        }
        if r > max {
            max = r;
        }
    }
    Some(max)
}

// ===========================================================================
// Lucky family TPS546 limit set (pure source of truth, host-tested)
// ===========================================================================

/// TPS546 protection-limit values shared by the whole Lucky LVxx family
/// (LV06 / LV07 / LV08 — one value set, applied to EVERY regulator the model
/// carries). `power::Tps546Config::lucky_lv08()` / `lucky_single()` MUST build
/// from this const so the numbers stay host-tested; never re-introduce literal
/// copies in `power.rs`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LuckyTps546Limits {
    /// Input turn-on threshold (V).
    pub vin_on: f32,
    /// Input turn-off threshold (V).
    pub vin_off: f32,
    /// Input undervoltage warning (V).
    pub vin_uv_warn: f32,
    /// Input overvoltage fault (V).
    pub vin_ov_fault: f32,
    /// Nominal output voltage (V) — the 1.2 V single parallel domain.
    pub vout_nominal: f32,
    /// VOUT_MIN register clamp (V).
    pub vout_min: f32,
    /// VOUT_MAX register clamp (V).
    pub vout_max: f32,
    /// Per-regulator output overcurrent WARN (A).
    pub iout_oc_warn_a: f32,
    /// Per-regulator output overcurrent FAULT (A).
    pub iout_oc_fault_a: f32,
    /// VOUT_SCALE_LOOP gain.
    pub scale_loop: f32,
    /// Switching frequency (kHz).
    pub switch_freq_khz: u16,
    /// VOUT_OV_FAULT_LIMIT as a ratio of `vout_nominal`.
    pub vout_ov_fault_ratio: f32,
    /// VOUT_OV_WARN_LIMIT as a ratio of `vout_nominal`.
    pub vout_ov_warn_ratio: f32,
    /// VOUT_UV_WARN_LIMIT as a ratio of `vout_nominal`.
    pub vout_uv_warn_ratio: f32,
    /// VOUT_UV_FAULT_LIMIT as a ratio of `vout_nominal`.
    pub vout_uv_fault_ratio: f32,
}

/// Lucky LVxx TPS546 limits — vendor ground truth: LVXX `vcore.c:63-80`
/// (`case LV06/LV07/LV08`): VIN 11.5 on / 11.0 off / 11.0 UV-warn /
/// 14.0 OV-fault; scale-loop 0.25; VOUT_COMMAND **1.2 V**; IOUT OC
/// 35 A warn / 40 A fault PER REGULATOR; 650 kHz; single-phase; SYNC disabled.
///
/// ⚠️ THE 3.6 V TRAP (SPEC §1.1): LVXX HEAD deleted a 3.6 V / 0.125-scale /
/// 45–50 A LV08 case (it survives only as a comment at `vcore.c:82-97`).
/// NEVER resurrect those values — the LV08's nine BM1366 are PARALLEL on one
/// ~1.2 V rail, and 3.6 V on that rail destroys nine dies. The regression test
/// `lucky_limits_can_never_produce_a_setpoint_above_2v` pins this.
///
/// One deliberate divergence from vendor: `vout_max` is 2.0 V (vendor wrote
/// 3.0). The VOUT_MAX register is the IC's own last-line setpoint ceiling on a
/// rail whose nominal is 1.2 V and whose derived OV fault is 1.5 V — 2.0 V
/// (matching the shipping `single_asic()` 1.2 V-class value) is strictly
/// tighter/safer and enforces the no->2.0 V invariant in hardware.
pub const LUCKY_TPS546_LIMITS: LuckyTps546Limits = LuckyTps546Limits {
    vin_on: 11.5,
    vin_off: 11.0,
    vin_uv_warn: 11.0,
    vin_ov_fault: 14.0,
    vout_nominal: 1.2,
    vout_min: 1.0,
    vout_max: 2.0,
    iout_oc_warn_a: 35.0,
    iout_oc_fault_a: 40.0,
    scale_loop: 0.25,
    switch_freq_khz: 650,
    vout_ov_fault_ratio: 1.25,
    vout_ov_warn_ratio: 1.16,
    vout_uv_warn_ratio: 0.90,
    vout_uv_fault_ratio: 0.75,
};

/// Board-level power offset for the whole Lucky family (LVXX `power.c:24-37`,
/// `family.power_offset = 18`). Added ONCE to summed regulator output power.
pub const LUCKY_POWER_OFFSET_W: f32 = 18.0;

// ===========================================================================
// LV08 disambiguation probe classification (SPEC §3 step 4)
// ===========================================================================

/// Verdict of the read-only secondary-regulator probe on an AMBIGUOUS unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuckyProbeVerdict {
    /// Both 0x7F and 0x14 ACKed — the three-regulator LV08 signature.
    TripleRegulatorLv08,
    /// Neither ACKed — genuine BitAxe-class single-regulator hardware.
    NoSecondaryRegulators,
    /// Exactly one ACKed — contradictory hardware; stay ambiguous and let the
    /// caller REFUSE TO ENERGIZE (fail-closed per SPEC §3 step 5).
    Inconclusive,
}

/// Classify the result of probing the two LV08 secondary TPS546 addresses.
/// Pure decision only — the actual (read-only, Lucky-gated) bus probe lives in
/// `power::probe_lucky_lv08_secondary_regulators`.
pub const fn classify_lucky_probe(
    addr_7f_answers: bool,
    addr_14_answers: bool,
) -> LuckyProbeVerdict {
    match (addr_7f_answers, addr_14_answers) {
        (true, true) => LuckyProbeVerdict::TripleRegulatorLv08,
        (false, false) => LuckyProbeVerdict::NoSecondaryRegulators,
        _ => LuckyProbeVerdict::Inconclusive,
    }
}

/// The TPS546 protection-limit / fault-response register set.
///
/// These are the regulator's last-line hardware protection thresholds plus the
/// fault-RESPONSE policy bytes. They are written exactly once, by
/// `power::Tps546::configure_limits`, during `PowerManager` init. After init the
/// only legitimate runtime writes to the TPS546 are `VOUT_COMMAND` (0x21, the
/// per-tick core-voltage setpoint) and `OPERATION` (0x01, on/off) — neither of
/// which is in this set, so the guard never interferes with normal voltage
/// control.
///
/// Register codes are duplicated from the `power::pmbus` module **by value**
/// (this module is dependency-free and pure on purpose, and `power.rs` is
/// `cfg(target_os = "espidf")`-gated so it cannot be referenced from a host
/// test). The duplication is therefore kept in lockstep **manually**: any change
/// to a PMBus fault-limit/fault-response code in `power::pmbus` must be mirrored
/// here. These are PMBus standard command codes and must never be changed.
pub const PROTECTED_REGISTERS: &[u8] = &[
    // ── VOUT protection thresholds (ULINEAR16) ──────────────────────────────
    0x40, // VOUT_OV_FAULT_LIMIT  — output overvoltage FAULT (last-line)
    0x42, // VOUT_OV_WARN_LIMIT   — output overvoltage warning
    0x43, // VOUT_UV_WARN_LIMIT   — output undervoltage warning
    0x44, // VOUT_UV_FAULT_LIMIT  — output undervoltage FAULT
    0x2B, // VOUT_MIN             — output voltage floor clamp
    0x24, // VOUT_MAX             — output voltage ceiling clamp
    // ── VIN protection thresholds (Linear11) ────────────────────────────────
    0x55, // VIN_OV_FAULT_LIMIT   — input overvoltage FAULT
    0x58, // VIN_UV_WARN_LIMIT    — input undervoltage warning
    0x35, // VIN_ON               — input turn-on threshold
    0x36, // VIN_OFF              — input turn-off threshold
    // ── IOUT protection thresholds (Linear11) ───────────────────────────────
    0x46, // IOUT_OC_FAULT_LIMIT  — output overcurrent FAULT (last-line)
    0x4A, // IOUT_OC_WARN_LIMIT   — output overcurrent warning
    // ── Die over-temperature thresholds (Linear11) ──────────────────────────
    0x4F, // OT_FAULT_LIMIT       — TPS546 die over-temp FAULT (last-line)
    0x51, // OT_WARN_LIMIT        — TPS546 die over-temp warning
    // ── Fault-RESPONSE policy bytes (how the IC reacts to a fault) ───────────
    0x5F, // VIN_OV_FAULT_RESPONSE
    0x47, // IOUT_OC_FAULT_RESPONSE
    0x50, // OT_FAULT_RESPONSE
];

/// Returns `true` if `(addr, register)` targets a protected TPS546 fault-limit /
/// fault-response register.
///
/// `register` is the PMBus command code, i.e. the **first byte** of the I2C write
/// payload (`[reg, data..]`). A write whose payload is empty (a bare-address
/// probe / `CLEAR_FAULTS` is a single 0x03 byte, never in the protected set) is
/// not protected. Any write to a non-TPS546 address is not protected.
///
/// Covers the FULL guarded address set (`GUARDED_TPS546_ADDRS`): the primary
/// 0x24 plus the Lucky LV08 secondaries 0x7F/0x14, so all three of an LV08's
/// paralleled regulators get identical fault-limit protection. Arm/latch
/// semantics are unchanged — one `GuardState` per bus covers the whole set.
pub const fn is_protected_register(addr: u8, register: u8) -> bool {
    if !is_guarded_tps546_addr(addr) {
        return false;
    }
    // const-fn linear scan over the small fixed set.
    let mut i = 0;
    while i < PROTECTED_REGISTERS.len() {
        if PROTECTED_REGISTERS[i] == register {
            return true;
        }
        i += 1;
    }
    false
}

/// HAL-side latch state for the TPS546 fault-limit write guard.
///
/// Mirrors the spirit of DCENT_OS's per-bus denylist, but as an opt-in,
/// latch-after-init guard rather than an always-on address denylist (BitAxe has
/// no EEPROM to deny outright, and the protected registers MUST be writable
/// during init). Held by `i2c::I2cBus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardState {
    /// Whether the platform has opted into the fault-limit guard at all
    /// (XPSAFE-2 default-off). `false` ⇒ the guard is fully inert and every
    /// write behaves exactly as before this feature existed.
    pub armed: bool,
    /// Whether init has finished and the guard is now enforcing. Writes to the
    /// protected set are only blocked when `armed && latched`. Set once, at the
    /// end of `PowerManager` init, after the legitimate `configure_limits` pass.
    pub latched: bool,
    /// Count of protected-register writes refused since arm. Surfaced to
    /// telemetry/logs so a latent bug that keeps hammering a fault limit is
    /// visible instead of silent.
    pub blocked_count: u64,
}

impl Default for GuardState {
    /// Default-preserving: disarmed, not latched, nothing blocked. A board that
    /// never calls `arm()` keeps its exact pre-XPSAFE-2 behavior.
    fn default() -> Self {
        Self {
            armed: false,
            latched: false,
            blocked_count: 0,
        }
    }
}

impl GuardState {
    /// Opt into the fault-limit guard (does NOT start enforcing yet — call
    /// `latch()` after init). Idempotent.
    ///
    /// Not a `const fn` (it takes `&mut self`) so the module compiles on older
    /// toolchains that predate const-mutable-reference stabilization; the
    /// predicate methods below stay `const` for compile-time use in tests.
    pub fn arm(&mut self) {
        self.armed = true;
    }

    /// Begin enforcing the guard. No-op if not armed (so a stray latch on a
    /// board that never opted in can't accidentally start blocking). Idempotent.
    pub fn latch(&mut self) {
        if self.armed {
            self.latched = true;
        }
    }

    /// Is the guard currently enforcing writes? (`armed && latched`).
    pub const fn enforcing(&self) -> bool {
        self.armed && self.latched
    }

    /// Decide whether a write to `(addr, register)` must be refused.
    ///
    /// Returns `true` ONLY when the guard is enforcing AND the target is a
    /// protected TPS546 register. The caller is responsible for bumping
    /// `blocked_count` (via `record_block`) and returning a HAL error — keeping
    /// the decision pure and the side effect explicit.
    pub const fn is_write_blocked(&self, addr: u8, register: u8) -> bool {
        self.enforcing() && is_protected_register(addr, register)
    }

    /// Record that one protected-register write was refused. Saturating so a
    /// runaway bug can never wrap the counter back to a small number.
    /// Not `const` (takes `&mut self`) for older-toolchain compatibility.
    pub fn record_block(&mut self) {
        self.blocked_count = self.blocked_count.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_set_covers_the_last_line_fault_limits() {
        // The three last-line hardware protections MUST be protected.
        assert!(is_protected_register(TPS546_ADDR, 0x40)); // VOUT_OV_FAULT_LIMIT
        assert!(is_protected_register(TPS546_ADDR, 0x46)); // IOUT_OC_FAULT_LIMIT
        assert!(is_protected_register(TPS546_ADDR, 0x4F)); // OT_FAULT_LIMIT
        assert!(is_protected_register(TPS546_ADDR, 0x55)); // VIN_OV_FAULT_LIMIT
    }

    #[test]
    fn normal_voltage_control_registers_are_never_protected() {
        // The two registers the runtime touches every tick MUST stay writable
        // even when the guard is fully armed+latched, or normal mining breaks.
        // VOUT_COMMAND (0x21) and OPERATION (0x01) are not in the set.
        assert!(!is_protected_register(TPS546_ADDR, 0x21)); // VOUT_COMMAND
        assert!(!is_protected_register(TPS546_ADDR, 0x01)); // OPERATION
        assert!(!is_protected_register(TPS546_ADDR, 0x03)); // CLEAR_FAULTS (1-byte)
        assert!(!is_protected_register(TPS546_ADDR, 0x02)); // ON_OFF_CONFIG
                                                            // ...and read-only status / telemetry registers are never protected.
        assert!(!is_protected_register(TPS546_ADDR, 0x79)); // STATUS_WORD
        assert!(!is_protected_register(TPS546_ADDR, 0x8B)); // READ_VOUT
    }

    #[test]
    fn guard_never_touches_other_i2c_devices() {
        // DS4432U (0x48), INA260 (0x40 device addr), EMC2101 (0x4C),
        // EMC2103 (0x2E) — even a register code that collides with a protected
        // TPS546 code must NOT be guarded on a different device address.
        for &dev in &[0x48u8, 0x4C, 0x2E, 0x40, 0x49, 0x4A, 0x4B] {
            if dev == TPS546_ADDR {
                continue;
            }
            // 0x40 is a protected TPS546 reg code; on another device it's free.
            assert!(!is_protected_register(dev, 0x40));
            assert!(!is_protected_register(dev, 0x46));
            assert!(!is_protected_register(dev, 0x4F));
        }
    }

    #[test]
    fn guard_disarmed_by_default_blocks_nothing() {
        // XPSAFE-2 default-off: a fresh GuardState must let every write through,
        // including a protected register — default behavior is fully preserved.
        let g = GuardState::default();
        assert!(!g.armed);
        assert!(!g.latched);
        assert!(!g.enforcing());
        assert!(!g.is_write_blocked(TPS546_ADDR, 0x40));
        assert!(!g.is_write_blocked(TPS546_ADDR, 0x46));
    }

    #[test]
    fn armed_but_not_latched_does_not_enforce_during_init() {
        // Between arm() and latch() (i.e. during configure_limits) the
        // legitimate fault-limit writes MUST still go through.
        let mut g = GuardState::default();
        g.arm();
        assert!(g.armed);
        assert!(!g.enforcing());
        assert!(!g.is_write_blocked(TPS546_ADDR, 0x40));
    }

    #[test]
    fn armed_and_latched_blocks_only_protected_writes() {
        let mut g = GuardState::default();
        g.arm();
        g.latch();
        assert!(g.enforcing());
        // Protected fault-limit writes are now refused...
        assert!(g.is_write_blocked(TPS546_ADDR, 0x40));
        assert!(g.is_write_blocked(TPS546_ADDR, 0x4F));
        // ...but the live voltage setpoint + enable path are still allowed.
        assert!(!g.is_write_blocked(TPS546_ADDR, 0x21)); // VOUT_COMMAND
        assert!(!g.is_write_blocked(TPS546_ADDR, 0x01)); // OPERATION
                                                         // ...and a different device is entirely unaffected.
        assert!(!g.is_write_blocked(0x48, 0x40)); // DS4432U
    }

    #[test]
    fn latch_is_a_noop_without_arm() {
        // A stray latch() on a board that never opted in must not start blocking.
        let mut g = GuardState::default();
        g.latch();
        assert!(!g.armed);
        assert!(!g.latched);
        assert!(!g.enforcing());
        assert!(!g.is_write_blocked(TPS546_ADDR, 0x40));
    }

    #[test]
    fn record_block_counts_and_saturates() {
        let mut g = GuardState::default();
        g.arm();
        g.latch();
        g.record_block();
        g.record_block();
        assert_eq!(g.blocked_count, 2);
        // Saturating: priming near the ceiling must not wrap to a small value.
        g.blocked_count = u64::MAX - 1;
        g.record_block();
        g.record_block(); // would overflow without saturation
        assert_eq!(g.blocked_count, u64::MAX);
    }

    #[test]
    fn protected_set_has_no_accidental_overlap_with_runtime_writes() {
        // Defensive: enumerate the registers the *runtime* (post-init) path can
        // write and assert none of them are in the protected set. If a future
        // edit adds VOUT_COMMAND/OPERATION/ON_OFF_CONFIG/CLEAR_FAULTS to the set
        // it would brick normal mining — this test catches that at host-test time.
        const RUNTIME_WRITABLE: &[u8] = &[
            0x21, // VOUT_COMMAND (every-tick setpoint)
            0x01, // OPERATION (enable/disable)
            0x02, // ON_OFF_CONFIG (init, before latch)
            0x03, // CLEAR_FAULTS (fault-clear opcode; transient-CML tolerance)
        ];
        for &reg in RUNTIME_WRITABLE {
            assert!(
                !PROTECTED_REGISTERS.contains(&reg),
                "register 0x{reg:02x} is a runtime-writable command and must NOT \
                 be in PROTECTED_REGISTERS (would break normal voltage control)"
            );
        }
    }

    #[test]
    fn protected_set_is_deduplicated() {
        // A duplicate entry would be harmless functionally but signals a sloppy
        // edit; pin uniqueness so the table stays a clean source of truth.
        let mut seen = std::collections::BTreeSet::new();
        for &reg in PROTECTED_REGISTERS {
            assert!(seen.insert(reg), "duplicate protected register 0x{reg:02x}");
        }
    }

    // ── Lucky LV08 multi-regulator address policy ────────────────────────────

    #[test]
    fn lv08_address_set_is_exactly_the_vendor_triple_in_vendor_order() {
        // Vendor ground truth (LVXX TPS546.c:35): {0x24, 0x7F, 0x14} = U2,U1,U3.
        // ORDER matters (init/broadcast order) — assert the exact sequence.
        assert_eq!(LUCKY_LV08_TPS546_ADDRS, &[0x24, 0x7F, 0x14]);
        assert_eq!(tps546_addr_set(true), &[0x24, 0x7F, 0x14]);
        assert_eq!(LUCKY_LV08_SECONDARY_TPS546_ADDRS, &[0x7F, 0x14]);
    }

    #[test]
    fn every_non_lv08_board_gets_exactly_the_single_0x24_set() {
        // The selector's false-branch is what EVERY currently-shipping board and
        // the Lucky LV06/LV07 receive: exactly [0x24], nothing else.
        assert_eq!(tps546_addr_set(false), &[TPS546_ADDR]);
        assert_eq!(SINGLE_TPS546_ADDR_SET, &[0x24]);
        assert_eq!(SINGLE_TPS546_ADDR_SET.len(), 1);
    }

    #[test]
    fn guard_covers_all_three_lv08_regulator_addresses() {
        for &addr in GUARDED_TPS546_ADDRS {
            // Last-line fault limits protected at EVERY LV08 regulator address…
            assert!(is_protected_register(addr, 0x40), "VOUT_OV @ 0x{addr:02x}");
            assert!(is_protected_register(addr, 0x46), "IOUT_OC @ 0x{addr:02x}");
            assert!(is_protected_register(addr, 0x4F), "OT @ 0x{addr:02x}");
            assert!(is_protected_register(addr, 0x55), "VIN_OV @ 0x{addr:02x}");
            // …while the runtime setpoint/enable path stays writable everywhere.
            assert!(
                !is_protected_register(addr, 0x21),
                "VOUT_COMMAND @ 0x{addr:02x}"
            );
            assert!(
                !is_protected_register(addr, 0x01),
                "OPERATION @ 0x{addr:02x}"
            );
        }
        assert_eq!(GUARDED_TPS546_ADDRS, LUCKY_LV08_TPS546_ADDRS);
        // Enforcement across the whole set once armed+latched; nothing before.
        let mut g = GuardState::default();
        assert!(!g.is_write_blocked(0x7F, 0x40));
        assert!(!g.is_write_blocked(0x14, 0x40));
        g.arm();
        g.latch();
        assert!(g.is_write_blocked(0x24, 0x40));
        assert!(g.is_write_blocked(0x7F, 0x40));
        assert!(g.is_write_blocked(0x14, 0x46));
        assert!(!g.is_write_blocked(0x7F, 0x21)); // setpoint stays live
    }

    // ── Aggregation math (sum power/current, max vout/vin/temp, +18 W once) ──

    #[test]
    fn power_is_summed_across_regulators_with_the_18w_offset_added_once() {
        // Three regulators on one 1.2 V rail: Σ(v·i) + 18, per LVXX power.c:24-37.
        let pairs = [(1.2f32, 13.0f32), (1.19, 12.5), (1.21, 13.5)];
        let expected: f32 = 1.2 * 13.0 + 1.19 * 12.5 + 1.21 * 13.5 + 18.0;
        let got = sum_regulator_power_w(&pairs, LUCKY_POWER_OFFSET_W);
        assert!(
            (got - expected).abs() < 1e-4,
            "got {got}, expected {expected}"
        );
        // The offset is added exactly ONCE, not per regulator.
        let without = sum_regulator_power_w(&pairs, 0.0);
        assert!((got - without - 18.0).abs() < 1e-4);
        assert!((LUCKY_POWER_OFFSET_W - 18.0).abs() < f32::EPSILON);
        // Single-regulator degenerate case: v·i + offset (existing boards).
        let single = sum_regulator_power_w(&[(1.2, 20.0)], 5.0);
        assert!((single - (1.2 * 20.0 + 5.0)).abs() < 1e-4);
    }

    #[test]
    fn current_is_summed_and_vout_vin_temp_take_the_max() {
        let i = sum_regulator_current_a(&[13.0, 12.5, 13.5]);
        assert!((i - 39.0).abs() < 1e-4);
        assert_eq!(max_regulator_reading(&[1.19, 1.21, 1.20]), Some(1.21));
        assert_eq!(max_regulator_reading(&[11.9, 12.1, 12.0]), Some(12.1));
        assert_eq!(max_regulator_reading(&[61.0, 74.5, 68.0]), Some(74.5));
        assert_eq!(max_regulator_reading(&[]), None);
    }

    #[test]
    fn a_dead_regulator_reading_poisons_the_aggregate_instead_of_vanishing() {
        // SPEC §4: cached/failed reads must not be silently averaged away. A NaN
        // (the HALPWR-2 "field unavailable" sentinel) must poison every
        // aggregate, not be skipped by max() or absorbed by sum().
        let m = max_regulator_reading(&[1.2, f32::NAN, 1.19]).unwrap();
        assert!(m.is_nan(), "NaN reading must poison the max aggregate");
        assert!(sum_regulator_current_a(&[13.0, f32::NAN, 13.5]).is_nan());
        assert!(sum_regulator_power_w(&[(1.2, 13.0), (f32::NAN, 12.0)], 18.0).is_nan());
    }

    // ── Lucky limit set: vendor values + the 3.6 V trap regression ───────────

    #[test]
    fn lucky_limits_match_the_vendor_lvxx_shared_case() {
        // LVXX vcore.c:63-80, case LV06/LV07/LV08 (one shared value set).
        let l = &LUCKY_TPS546_LIMITS;
        assert_eq!(l.vin_on, 11.5);
        assert_eq!(l.vin_off, 11.0);
        assert_eq!(l.vin_uv_warn, 11.0);
        assert_eq!(l.vin_ov_fault, 14.0);
        assert_eq!(l.scale_loop, 0.25);
        assert_eq!(l.iout_oc_warn_a, 35.0);
        assert_eq!(l.iout_oc_fault_a, 40.0);
        assert_eq!(l.switch_freq_khz, 650);
        // Every vout limit is DERIVED from the 1.2 V nominal.
        assert_eq!(l.vout_nominal, 1.2);
        assert!((l.vout_nominal * l.vout_ov_fault_ratio - 1.5).abs() < 1e-6);
        assert!((l.vout_nominal * l.vout_uv_fault_ratio - 0.9).abs() < 1e-6);
    }

    #[test]
    fn lucky_limits_can_never_produce_a_setpoint_above_2v() {
        // THE 3.6 V TRAP (SPEC §1.1): the deleted LVXX 3.6 V / 0.125-scale /
        // 45-50 A LV08 case must never be resurrected — nine PARALLEL BM1366
        // on one ~1.2 V rail. Pin every avenue by which a >2.0 V setpoint or
        // its fingerprint could re-enter the Lucky preset.
        let l = &LUCKY_TPS546_LIMITS;
        assert!(l.vout_nominal <= 1.3, "Lucky nominal must stay ~1.2 V");
        assert!(
            l.vout_max <= 2.0,
            "VOUT_MAX register clamp must stay ≤ 2.0 V"
        );
        assert!(
            l.vout_nominal * l.vout_ov_fault_ratio <= 2.0,
            "derived OV fault limit must stay ≤ 2.0 V"
        );
        assert!(l.vout_min < l.vout_nominal && l.vout_nominal < l.vout_max);
        // Fingerprints of the deleted 3.6 V case, individually banned:
        assert_ne!(
            l.vout_nominal, 3.6,
            "3.6 V nominal is the deleted LV08 case"
        );
        assert_ne!(
            l.scale_loop, 0.125,
            "0.125 scale-loop is the deleted LV08 case"
        );
        assert_ne!(l.iout_oc_warn_a, 45.0, "45 A warn is the deleted LV08 case");
        assert_ne!(
            l.iout_oc_fault_a, 50.0,
            "50 A fault is the deleted LV08 case"
        );
    }

    // ── Disambiguation probe classification (SPEC §3 step 4) ─────────────────

    #[test]
    fn probe_classification_truth_table() {
        assert_eq!(
            classify_lucky_probe(true, true),
            LuckyProbeVerdict::TripleRegulatorLv08
        );
        assert_eq!(
            classify_lucky_probe(false, false),
            LuckyProbeVerdict::NoSecondaryRegulators
        );
        // A half-answering unit is contradictory hardware — must stay
        // Inconclusive so the caller refuses to energize (fail-closed).
        assert_eq!(
            classify_lucky_probe(true, false),
            LuckyProbeVerdict::Inconclusive
        );
        assert_eq!(
            classify_lucky_probe(false, true),
            LuckyProbeVerdict::Inconclusive
        );
    }
}
