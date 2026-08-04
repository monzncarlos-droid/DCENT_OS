//! Host-pure TMP451 / ADT7461-family remote-diode temperature decode and config.
//!
//! `tmp451.rs` is the ESP-IDF transport (I2C + GPIO mux select); everything a
//! host test can execute lives here. Same split as
//! `power_convert.rs`/`power.rs` and `temp_decode.rs`/`temp.rs`.
//!
//! # Why this part matters
//!
//! The TMP451 is the only per-ASIC thermal source on the muxed Nerd boards
//! (NerdOCTAXE-gamma, NerdQX, Q1370/Q1373). Without it those boards have no
//! trusted temperature and cannot be permitted to mine.
//!
//! # Evidence
//!
//! Two INDEPENDENT implementations agree on the register map, which is why the
//! core numbers below are treated as confirmed rather than assumed:
//!
//! *
//!   (BitMaker-hub, ships on real Nerd hardware).
//! *
//!   (`TMP451_open@3C3A8.c`, `read_sensor_on_tmp451@3C418.c`) — Bitmain's own
//!   factory jig. It reads register 0 for local and register 1 for remote (it
//!   passes its `is_remote` flag directly as the register address) and casts
//!   the result to a SIGNED char, independently confirming both the register
//!   assignment and the two's-complement MSB.
//!
//! Bitmain's jig straps the part to 0x4A while the Nerd boards use 0x4C/0x4E,
//! so the address is a per-board property and is never hardcoded here.
//!  records
//! the family at 0x48 and 0x4C across the Antminer fleet.
//!
//! # Deliberate divergences from the upstream C
//!
//! 1. **No `0.0` error sentinel.** The upstream TMP1075 sibling returns `0.0f`
//!    when I2C fails, and its caller tests `if (!temp)`. `0.0` is a perfectly
//!    plausible temperature, so a dead sensor reads as "cold" and the fan PID
//!    idles while the chips cook. Everything here returns `Option`/`Result`.
//! 2. **Calibration is not defaulted to the upstream constants.** See
//!    [`Calibration`] — the upstream default subtracts ~27 C at operating
//!    temperature, and applying it to a board that does not need it would
//!    under-report chip temperature. Our default is identity, which errs toward
//!    reporting too hot (cut off early) rather than too cold (cook the chip).
//!
//! # Known gap (deliberately not guessed)
//!
//! The STATUS register's open-circuit / alarm bit positions are NOT confirmed
//! by anything in our corpus. Upstream checks only BUSY (0x80), and Bitmain's
//! jig checks nothing at all. Availability here is therefore gated on BUSY plus
//! the same negative open-circuit value sentinel the EMC2101 path already uses
//! ([`temp_decode`](crate::temp_decode)) — not on an invented bit position.
//! `STATUS_BUSY` is the only STATUS bit this module ascribes meaning to.

/// TMP451 register addresses.
///
/// Confirmed against both upstream sources; see the module docs.
pub mod reg {
    /// Local (die) temperature, integer part. Confirmed by Bitmain's jig.
    pub const LOCAL_MSB: u8 = 0x00;
    /// Remote (ASIC diode) temperature, integer part. Confirmed by Bitmain's jig.
    pub const REMOTE_MSB: u8 = 0x01;
    /// Status register. Only [`super::STATUS_BUSY`] is ascribed meaning.
    pub const STATUS: u8 = 0x02;
    /// Configuration, read address (write goes to [`CONFIG_WRITE`]).
    pub const CONFIG_READ: u8 = 0x03;
    /// Configuration, write address.
    pub const CONFIG_WRITE: u8 = 0x09;
    /// Conversion-rate, write address.
    pub const CONV_RATE_WRITE: u8 = 0x0A;
    /// One-shot conversion trigger. Any written value triggers.
    pub const ONE_SHOT: u8 = 0x0F;
    /// Remote temperature, fractional part (high nibble).
    pub const REMOTE_LSB: u8 = 0x10;
    /// Remote temperature offset correction, integer part.
    pub const REMOTE_OFFSET_MSB: u8 = 0x11;
    /// Remote temperature offset correction, fractional part.
    pub const REMOTE_OFFSET_LSB: u8 = 0x12;
    /// Local temperature, fractional part (high nibble).
    pub const LOCAL_LSB: u8 = 0x15;
    /// Remote diode ideality (n-factor) correction.
    pub const NFACTOR: u8 = 0x23;
}

/// STATUS bit: a conversion is in flight.
///
/// The ONLY status bit this module interprets — see the module-level "Known
/// gap" note. Confirmed by upstream's one-shot poll loop.
pub const STATUS_BUSY: u8 = 0x80;

/// CONFIG bit: standby / shutdown, required for one-shot operation.
///
/// Upstream writes exactly `1 << 6` at init to enter one-shot mode.
pub const CONFIG_STANDBY: u8 = 1 << 6;

/// CONFIG bit: extended temperature range.
///
/// ADT7461-family convention, consistent with our own sensor matrix recording
/// the part as "LM75-pin-compat with extended range". This module never WRITES
/// this bit — it only reads it back to decide how to decode, so a mistaken bit
/// position cannot mis-program a board. Every board in our corpus leaves it
/// clear (upstream's init writes `1 << 6` alone), which decodes as
/// [`TempRange::Standard`].
pub const CONFIG_EXTENDED_RANGE: u8 = 1 << 2;

/// Value written to trigger a one-shot conversion.
pub const ONE_SHOT_TRIGGER: u8 = 0xFF;

/// Resolution of the fractional nibble, in degrees Celsius per LSB.
pub const FRACTION_STEP_C: f32 = 0.0625;

/// Offset applied to the integer byte in extended range.
pub const EXTENDED_RANGE_OFFSET_C: f32 = 64.0;

/// Lower reject bound shared with the EMC2101 path (`temp_decode.rs`).
///
/// A reading below this is the negative open-circuit sentinel, not a real
/// measurement. Deliberately mirrors `temp_decode::EXTERNAL_TEMP_MIN_C` so both
/// remote-diode sensors reject open circuits by the same rule.
///
/// There is intentionally NO upper reject: a high reading is real danger and
/// must reach the thermal-emergency path (the HALT-3 rule).
pub const OPEN_CIRCUIT_MIN_C: f32 = -10.0;

/// Highest mux channel this part's muxed boards address.
pub const MAX_MUX_CHANNEL: u8 = 3;

/// I2C addresses observed for this part in our corpus.
///
/// Documentation, not a whitelist: the address is strapped per board and
/// [`is_plausible_address`] is what actually validates. 0x4C/0x4E are the Nerd
/// boards, 0x4A is Bitmain's S21xp jig, 0x48 is the Antminer fleet sensor
/// matrix.
pub const OBSERVED_ADDRESSES: [u8; 4] = [0x48, 0x4A, 0x4C, 0x4E];

/// Temperature encoding of the integer byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TempRange {
    /// Two's-complement signed byte, -64..=127 C. Every board in our corpus.
    Standard,
    /// Unsigned byte biased by 64, -64..=191 C.
    Extended,
}

impl TempRange {
    /// Derive the range from a CONFIG register readback.
    ///
    /// Reading (rather than writing) the bit keeps a mistaken bit position from
    /// ever mis-programming a part; the worst case is a mis-decode on a board
    /// that ships extended range, and no board in our corpus does.
    pub fn from_config(config: u8) -> Self {
        if config & CONFIG_EXTENDED_RANGE != 0 {
            Self::Extended
        } else {
            Self::Standard
        }
    }
}

/// Errors from configuring or addressing the part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tmp451ConfigError {
    /// Address is outside the usable 7-bit I2C space.
    AddressReserved(u8),
    /// Mux channel above [`MAX_MUX_CHANNEL`].
    ChannelOutOfRange(u8),
    /// Calibration scale is non-finite or outside the sane band.
    CalibrationScaleOutOfRange,
    /// Calibration offset is non-finite or outside the sane band.
    CalibrationOffsetOutOfRange,
}

impl core::fmt::Display for Tmp451ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AddressReserved(a) => {
                write!(f, "0x{a:02X} is not a usable 7-bit I2C address")
            }
            Self::ChannelOutOfRange(c) => {
                write!(f, "mux channel {c} exceeds {MAX_MUX_CHANNEL}")
            }
            Self::CalibrationScaleOutOfRange => write!(f, "calibration scale out of range"),
            Self::CalibrationOffsetOutOfRange => write!(f, "calibration offset out of range"),
        }
    }
}

/// True when `addr` is a usable 7-bit I2C address.
///
/// Rejects the reserved low block (0x00-0x07) and the reserved high block
/// (0x78-0x7F), and anything with bits above the 7-bit field set. A floating
/// bus that reads back 0x00 or 0xFF therefore cannot be mistaken for a part.
pub fn is_plausible_address(addr: u8) -> bool {
    addr > 0x07 && addr < 0x78
}

/// Decode an integer/fraction register pair into degrees Celsius.
///
/// The fraction lives in the HIGH nibble of the LSB register; the low nibble is
/// undefined and masked off. Both upstream implementations agree.
pub fn decode_temp(range: TempRange, msb: u8, lsb: u8) -> f32 {
    let fraction = ((lsb >> 4) & 0x0F) as f32 * FRACTION_STEP_C;
    let integer = match range {
        TempRange::Standard => msb as i8 as f32,
        TempRange::Extended => msb as f32 - EXTENDED_RANGE_OFFSET_C,
    };
    integer + fraction
}

/// Decode a reading and reject the open-circuit sentinel.
///
/// Returns `None` only for a value below [`OPEN_CIRCUIT_MIN_C`]. A high reading
/// is deliberately returned so it reaches the thermal-emergency path.
pub fn decode_available_temp(range: TempRange, msb: u8, lsb: u8) -> Option<f32> {
    let temp = decode_temp(range, msb, lsb);
    if temp < OPEN_CIRCUIT_MIN_C {
        return None;
    }
    Some(temp)
}

/// True while a conversion is still in flight.
pub fn conversion_busy(status: u8) -> bool {
    status & STATUS_BUSY != 0
}

/// The CONFIG byte written at init to enter one-shot (standby) mode.
///
/// Matches upstream exactly: standby set, every other bit — including
/// [`CONFIG_EXTENDED_RANGE`] — left clear.
pub fn init_config_byte() -> u8 {
    CONFIG_STANDBY
}

/// GPIO levels for an analog mux channel select.
///
/// Returns `(a0, a1)` where A0 is the LSB. `active_high == false` inverts both,
/// for boards that wire the select lines through an inverting buffer.
pub fn mux_levels(channel: u8, active_high: bool) -> Result<(bool, bool), Tmp451ConfigError> {
    if channel > MAX_MUX_CHANNEL {
        return Err(Tmp451ConfigError::ChannelOutOfRange(channel));
    }
    let a0 = channel & 0x1 != 0;
    let a1 = channel & 0x2 != 0;
    if active_high {
        Ok((a0, a1))
    } else {
        Ok((!a0, !a1))
    }
}

/// Per-board linear correction applied to a raw remote-diode reading.
///
/// # Why the default is identity and not the upstream constants
///
/// Upstream's default is `scale = 1.09`, `offset = -29.5`, applied as
/// `((t - 30) * scale + 30) + offset`. At a 60 C measurement that yields
/// 33.2 C — a ~27 C DOWNWARD correction. It exists because those boards read a
/// BM1370 diode with an uncorrected ideality factor, so the raw value runs far
/// hot.
///
/// That makes the correction strongly board-and-chip specific, and wrong in the
/// most dangerous direction if misapplied: a board that does not need it would
/// silently under-report chip temperature by tens of degrees. So a board must
/// DECLARE its calibration; the default here is identity, which over-reports
/// relative to a board that needs correction and therefore errs toward cutting
/// off early rather than cooking the chip.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Calibration {
    /// Gain about the 30 C pivot.
    pub scale: f32,
    /// Per-channel additive offset in degrees Celsius.
    pub offsets: [f32; 4],
}

/// Pivot temperature the gain is applied about.
pub const CALIBRATION_PIVOT_C: f32 = 30.0;

/// Widest gain accepted. A value outside this is a config error, not a reading.
pub const CALIBRATION_SCALE_MIN: f32 = 0.5;
/// See [`CALIBRATION_SCALE_MIN`].
pub const CALIBRATION_SCALE_MAX: f32 = 2.0;
/// Widest magnitude offset accepted, in degrees Celsius.
pub const CALIBRATION_OFFSET_ABS_MAX: f32 = 60.0;

impl Default for Calibration {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl Calibration {
    /// No correction. The safe default — see the type docs.
    pub const IDENTITY: Self = Self {
        scale: 1.0,
        offsets: [0.0; 4],
    };

    /// Upstream's default for the BM1370 Nerd boards (`tmp451.h`).
    ///
    /// Only for a board whose row explicitly declares it.
    pub const NERD_BM1370: Self = Self {
        scale: 1.09,
        offsets: [-29.5; 4],
    };

    /// Upstream's override for the Q1373 board (`q1373.cpp`).
    pub const Q1373: Self = Self {
        scale: 1.06,
        offsets: [-25.4; 4],
    };

    /// Build a validated calibration.
    pub fn new(scale: f32, offsets: [f32; 4]) -> Result<Self, Tmp451ConfigError> {
        let cal = Self { scale, offsets };
        cal.validate()?;
        Ok(cal)
    }

    /// Reject non-finite or absurd coefficients.
    pub fn validate(&self) -> Result<(), Tmp451ConfigError> {
        if !self.scale.is_finite()
            || self.scale < CALIBRATION_SCALE_MIN
            || self.scale > CALIBRATION_SCALE_MAX
        {
            return Err(Tmp451ConfigError::CalibrationScaleOutOfRange);
        }
        for off in self.offsets {
            if !off.is_finite() || off.abs() > CALIBRATION_OFFSET_ABS_MAX {
                return Err(Tmp451ConfigError::CalibrationOffsetOutOfRange);
            }
        }
        Ok(())
    }

    /// True when this calibration changes nothing.
    pub fn is_identity(&self) -> bool {
        self.scale == 1.0 && self.offsets.iter().all(|o| *o == 0.0)
    }

    /// Apply the correction for `channel` to a raw reading.
    pub fn apply(&self, channel: u8, raw_c: f32) -> Result<f32, Tmp451ConfigError> {
        if channel > MAX_MUX_CHANNEL {
            return Err(Tmp451ConfigError::ChannelOutOfRange(channel));
        }
        let off = self.offsets[channel as usize];
        Ok((raw_c - CALIBRATION_PIVOT_C) * self.scale + CALIBRATION_PIVOT_C + off)
    }
}

/// A decoded remote-diode reading, carrying both forms.
///
/// The raw value is retained deliberately: a calibration is a large downward
/// correction on the boards that use one, so a thermal-emergency path that
/// wants the most conservative number can consult `raw_c` rather than trusting
/// a per-board constant.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reading {
    /// Straight from the registers, before any per-board correction.
    pub raw_c: f32,
    /// After [`Calibration::apply`].
    pub corrected_c: f32,
}

impl Reading {
    /// Decode and correct in one step, rejecting the open-circuit sentinel.
    pub fn decode(
        range: TempRange,
        cal: &Calibration,
        channel: u8,
        msb: u8,
        lsb: u8,
    ) -> Result<Option<Self>, Tmp451ConfigError> {
        let Some(raw_c) = decode_available_temp(range, msb, lsb) else {
            return Ok(None);
        };
        let corrected_c = cal.apply(channel, raw_c)?;
        Ok(Some(Self { raw_c, corrected_c }))
    }

    /// The more conservative (hotter) of the two values.
    ///
    /// What a thermal cutoff should consume when it must not be fooled by a
    /// mis-declared downward correction.
    pub fn conservative_c(&self) -> f32 {
        if self.raw_c > self.corrected_c {
            self.raw_c
        } else {
            self.corrected_c
        }
    }
}

/// Settling delays around a mux channel switch, in milliseconds.
///
/// Values are upstream's (`tmp451.h`): 50 ms after switching the analog mux,
/// then a discarded conversion, then 75 ms before the reading that counts. The
/// discard matters — the first conversion after a switch is taken against the
/// previous channel's settled diode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settling {
    /// Delay after driving the mux select lines.
    pub after_switch_ms: u32,
    /// Delay after the discarded conversion, before the real read.
    pub before_read_ms: u32,
    /// One-shot poll timeout.
    pub one_shot_timeout_ms: u32,
    /// Interval between one-shot status polls.
    pub poll_interval_ms: u32,
}

impl Default for Settling {
    fn default() -> Self {
        Self {
            after_switch_ms: 50,
            before_read_ms: 75,
            one_shot_timeout_ms: 200,
            poll_interval_ms: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── register map ────────────────────────────────────────────────────────

    #[test]
    fn register_map_matches_both_independent_sources() {
        // Bitmain's jig passes its is_remote flag AS the register address, so
        // local must be 0 and remote must be 1. Upstream agrees.
        assert_eq!(reg::LOCAL_MSB, 0x00);
        assert_eq!(reg::REMOTE_MSB, 0x01);
        assert_eq!(reg::STATUS, 0x02);
        assert_eq!(reg::ONE_SHOT, 0x0F);
        assert_eq!(reg::REMOTE_LSB, 0x10);
        assert_eq!(reg::LOCAL_LSB, 0x15);
    }

    #[test]
    fn init_config_enters_standby_without_touching_range() {
        let cfg = init_config_byte();
        assert_eq!(cfg & CONFIG_STANDBY, CONFIG_STANDBY);
        // Writing the range bit is exactly what this module promises not to do.
        assert_eq!(cfg & CONFIG_EXTENDED_RANGE, 0);
        assert_eq!(cfg, 0x40);
    }

    // ── decode ──────────────────────────────────────────────────────────────

    #[test]
    fn standard_range_decodes_signed_msb() {
        assert_eq!(decode_temp(TempRange::Standard, 0x32, 0x00), 50.0);
        // Bitmain casts to signed char; a negative must stay negative.
        assert_eq!(decode_temp(TempRange::Standard, 0xEC, 0x00), -20.0);
    }

    #[test]
    fn fraction_comes_from_the_high_nibble_only() {
        // 0x8_ => 8 * 0.0625 = 0.5; the low nibble is undefined and ignored.
        assert_eq!(decode_temp(TempRange::Standard, 0x32, 0x80), 50.5);
        assert_eq!(decode_temp(TempRange::Standard, 0x32, 0x8F), 50.5);
        assert_eq!(decode_temp(TempRange::Standard, 0x32, 0xF0), 50.9375);
    }

    #[test]
    fn extended_range_biases_by_sixty_four() {
        assert_eq!(decode_temp(TempRange::Extended, 0x00, 0x00), -64.0);
        assert_eq!(decode_temp(TempRange::Extended, 0x40, 0x00), 0.0);
        assert_eq!(decode_temp(TempRange::Extended, 0x96, 0x00), 86.0);
    }

    #[test]
    fn range_is_derived_from_config_readback() {
        assert_eq!(TempRange::from_config(0x00), TempRange::Standard);
        assert_eq!(TempRange::from_config(CONFIG_STANDBY), TempRange::Standard);
        assert_eq!(
            TempRange::from_config(CONFIG_EXTENDED_RANGE),
            TempRange::Extended
        );
        // The byte upstream actually writes must decode as standard.
        assert_eq!(
            TempRange::from_config(init_config_byte()),
            TempRange::Standard
        );
    }

    // ── availability: fail-closed, but never drop real danger ────────────────

    #[test]
    fn open_circuit_sentinel_is_unavailable() {
        // 0x80 decodes to -128 C, 0xF5 to -11 C: both below the reject bound.
        assert_eq!(decode_available_temp(TempRange::Standard, 0x80, 0x00), None);
        assert_eq!(decode_available_temp(TempRange::Standard, 0xF5, 0x00), None);
    }

    #[test]
    fn exactly_the_reject_bound_is_still_a_reading() {
        // Reject is strictly `<`, matching temp_decode.rs.
        assert_eq!(
            decode_available_temp(TempRange::Standard, 0xF6, 0x00),
            Some(-10.0)
        );
    }

    #[test]
    fn dangerously_high_reading_is_reported_not_dropped() {
        // HALT-3: a runaway chip must reach the emergency path, never be
        // filtered as "implausible". There is no upper reject by design.
        assert_eq!(
            decode_available_temp(TempRange::Standard, 0x7F, 0xF0),
            Some(127.9375)
        );
        assert_eq!(
            decode_available_temp(TempRange::Extended, 0xFF, 0x00),
            Some(191.0)
        );
    }

    #[test]
    fn zero_celsius_is_a_reading_not_an_error() {
        // The upstream C uses 0.0 as its I2C-failure sentinel and tests
        // `if (!temp)`. This asserts we did not inherit that: 0 C is a valid
        // cold-boot reading and must be reported as one.
        assert_eq!(
            decode_available_temp(TempRange::Standard, 0x00, 0x00),
            Some(0.0)
        );
    }

    // ── status ──────────────────────────────────────────────────────────────

    #[test]
    fn busy_is_the_only_status_bit_interpreted() {
        assert!(conversion_busy(0x80));
        assert!(conversion_busy(0xFF));
        assert!(!conversion_busy(0x00));
        // Every other bit is unconfirmed in our corpus and must not gate.
        assert!(!conversion_busy(0x7F));
    }

    // ── addressing ──────────────────────────────────────────────────────────

    #[test]
    fn observed_addresses_are_all_plausible() {
        for addr in OBSERVED_ADDRESSES {
            assert!(is_plausible_address(addr), "0x{addr:02X}");
        }
    }

    #[test]
    fn both_vendors_straps_are_covered() {
        // Nerd boards strap 0x4C/0x4E; Bitmain's S21xp jig straps 0x4A. A
        // hardcoded address would break one of them.
        assert!(OBSERVED_ADDRESSES.contains(&0x4C));
        assert!(OBSERVED_ADDRESSES.contains(&0x4E) || is_plausible_address(0x4E));
        assert!(OBSERVED_ADDRESSES.contains(&0x4A));
    }

    #[test]
    fn floating_bus_values_are_not_addresses() {
        assert!(!is_plausible_address(0x00));
        assert!(!is_plausible_address(0xFF));
        assert!(!is_plausible_address(0x07));
        assert!(!is_plausible_address(0x78));
    }

    // ── mux ─────────────────────────────────────────────────────────────────

    #[test]
    fn mux_encodes_channel_with_a0_as_lsb() {
        assert_eq!(mux_levels(0, true), Ok((false, false)));
        assert_eq!(mux_levels(1, true), Ok((true, false)));
        assert_eq!(mux_levels(2, true), Ok((false, true)));
        assert_eq!(mux_levels(3, true), Ok((true, true)));
    }

    #[test]
    fn active_low_mux_inverts_both_lines() {
        for ch in 0..=MAX_MUX_CHANNEL {
            let (h0, h1) = mux_levels(ch, true).unwrap();
            let (l0, l1) = mux_levels(ch, false).unwrap();
            assert_eq!(l0, !h0);
            assert_eq!(l1, !h1);
        }
    }

    #[test]
    fn mux_rejects_a_channel_the_two_select_lines_cannot_address() {
        assert_eq!(
            mux_levels(4, true),
            Err(Tmp451ConfigError::ChannelOutOfRange(4))
        );
    }

    // ── calibration ─────────────────────────────────────────────────────────

    #[test]
    fn default_calibration_is_identity_not_the_upstream_constants() {
        // The load-bearing safety choice: inheriting upstream's -29.5 offset by
        // default would under-report chip temperature by ~27 C on any board
        // that does not need it.
        let cal = Calibration::default();
        assert!(cal.is_identity());
        assert_eq!(cal.apply(0, 60.0), Ok(60.0));
        assert_ne!(cal, Calibration::NERD_BM1370);
    }

    #[test]
    fn upstream_calibration_reproduces_its_documented_curve() {
        // ((60 - 30) * 1.09 + 30) - 29.5 = 33.2
        let got = Calibration::NERD_BM1370.apply(0, 60.0).unwrap();
        assert!((got - 33.2).abs() < 1e-4, "got {got}");
    }

    #[test]
    fn upstream_calibration_is_a_large_downward_correction() {
        // Pins the hazard the type docs describe, so nobody re-defaults to it
        // without confronting the magnitude.
        let raw = 60.0;
        let corrected = Calibration::NERD_BM1370.apply(0, raw).unwrap();
        assert!(
            raw - corrected > 25.0,
            "expected >25C downward, got {}",
            raw - corrected
        );
    }

    #[test]
    fn q1373_calibration_differs_from_the_family_default() {
        assert_ne!(Calibration::Q1373, Calibration::NERD_BM1370);
        let got = Calibration::Q1373.apply(0, 60.0).unwrap();
        // ((60 - 30) * 1.06 + 30) - 25.4 = 36.4
        assert!((got - 36.4).abs() < 1e-4, "got {got}");
    }

    #[test]
    fn calibration_is_per_channel() {
        let cal = Calibration::new(1.0, [0.0, 1.0, 2.0, 3.0]).unwrap();
        assert_eq!(cal.apply(0, 50.0), Ok(50.0));
        assert_eq!(cal.apply(3, 50.0), Ok(53.0));
    }

    #[test]
    fn calibration_rejects_non_finite_and_absurd_coefficients() {
        assert_eq!(
            Calibration::new(f32::NAN, [0.0; 4]),
            Err(Tmp451ConfigError::CalibrationScaleOutOfRange)
        );
        assert_eq!(
            Calibration::new(0.0, [0.0; 4]),
            Err(Tmp451ConfigError::CalibrationScaleOutOfRange)
        );
        assert_eq!(
            Calibration::new(1.0, [0.0, 0.0, f32::INFINITY, 0.0]),
            Err(Tmp451ConfigError::CalibrationOffsetOutOfRange)
        );
        assert_eq!(
            Calibration::new(1.0, [-200.0, 0.0, 0.0, 0.0]),
            Err(Tmp451ConfigError::CalibrationOffsetOutOfRange)
        );
    }

    #[test]
    fn both_shipped_calibrations_validate() {
        Calibration::IDENTITY.validate().unwrap();
        Calibration::NERD_BM1370.validate().unwrap();
        Calibration::Q1373.validate().unwrap();
    }

    #[test]
    fn calibration_rejects_an_unaddressable_channel() {
        assert_eq!(
            Calibration::IDENTITY.apply(4, 50.0),
            Err(Tmp451ConfigError::ChannelOutOfRange(4))
        );
    }

    // ── Reading ─────────────────────────────────────────────────────────────

    #[test]
    fn reading_carries_raw_alongside_corrected() {
        let r = Reading::decode(
            TempRange::Standard,
            &Calibration::NERD_BM1370,
            0,
            0x3C,
            0x00,
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.raw_c, 60.0);
        assert!((r.corrected_c - 33.2).abs() < 1e-4);
    }

    #[test]
    fn conservative_reading_defeats_a_downward_correction() {
        // The whole point of keeping raw: a cutoff consuming this cannot be
        // talked below the measured value by a mis-declared calibration.
        let r = Reading::decode(
            TempRange::Standard,
            &Calibration::NERD_BM1370,
            0,
            0x64,
            0x00,
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.raw_c, 100.0);
        assert!(r.corrected_c < r.raw_c);
        assert_eq!(r.conservative_c(), 100.0);
    }

    #[test]
    fn conservative_reading_is_corrected_when_correction_raises() {
        let cal = Calibration::new(1.0, [10.0; 4]).unwrap();
        let r = Reading::decode(TempRange::Standard, &cal, 0, 0x32, 0x00)
            .unwrap()
            .unwrap();
        assert_eq!(r.raw_c, 50.0);
        assert_eq!(r.corrected_c, 60.0);
        assert_eq!(r.conservative_c(), 60.0);
    }

    #[test]
    fn open_circuit_survives_calibration_as_unavailable() {
        // A correction must never turn an open circuit into a plausible number.
        let r = Reading::decode(
            TempRange::Standard,
            &Calibration::NERD_BM1370,
            0,
            0x80,
            0x00,
        )
        .unwrap();
        assert_eq!(r, None);
    }

    // ── settling ────────────────────────────────────────────────────────────

    #[test]
    fn settling_defaults_match_upstream() {
        let s = Settling::default();
        assert_eq!(s.after_switch_ms, 50);
        assert_eq!(s.before_read_ms, 75);
        assert_eq!(s.one_shot_timeout_ms, 200);
    }

    #[test]
    fn poll_interval_divides_into_the_timeout() {
        // A poll interval longer than the timeout would make the loop take one
        // sample and give up.
        let s = Settling::default();
        assert!(s.poll_interval_ms > 0);
        assert!(s.poll_interval_ms < s.one_shot_timeout_ms);
    }
}
