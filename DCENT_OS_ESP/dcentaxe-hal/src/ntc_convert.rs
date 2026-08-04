//! Pure NTC-thermistor-on-ADC temperature conversion (no ESP-IDF dependency).
//!
//! Every temperature sensor the registry drives today is an I2C part (EMC2101,
//! EMC2103, EMC2302, TMP451, TMP1075). This is the first of a different class:
//! a plain NTC thermistor in a resistor divider, read through an ESP32 ADC
//! channel. It is host-pure so the divider algebra, the beta equation and — most
//! importantly — the fail-closed input validation all run in the host test gate
//! with no hardware. The esp-idf ADC transport lives in `ntc` (feature-gated).
//!
//! # The circuit
//!
//! ```text
//!         3V3
//!          |
//!         [ ] R_pullup (10 k)
//!          |
//!          +------> ADC channel   (V_out)
//!          |
//!         [ ] NTC   (10 k @ 25 C)
//!          |
//!         GND
//! ```
//!
//! The NTC sits on the LOW side, so its resistance — and therefore `V_out` —
//! FALLS as temperature RISES. Two consequences worth stating because they
//! decide the failure modes:
//!
//! 1. The hot end of the range maps to the low end of the ADC, where there is
//!    plenty of resolution. ADC saturation near the top rail costs COLD-end
//!    accuracy only, which is the harmless direction for a safety sensor.
//! 2. A short to ground reads as `V_out -> 0`, i.e. resistance -> 0, i.e.
//!    temperature -> +infinity. That reports ABSURDLY HOT and trips thermal
//!    protection. Also the harmless direction. An open circuit reads as
//!    `V_out -> VREF`, which [`celsius_from_millivolts`] REJECTS rather than
//!    reporting as absurdly cold — see below.
//!
//! # Provenance
//!
//! The formula and both constants are the vendor's own, from the BitForge Nano
//! firmware:
//!
//! ```c
//! #define BETA 3380  // Beta value of the thermistor
//! #define R0 10000   // Resistance at 25°C (10kΩ)
//! float thermistor_resistance = R0 * (voltage / (3.3 - voltage));
//! float temperature_kelvin = (float)(BETA / (log(thermistor_resistance / R0) + (BETA / 298.15)));
//! return temperature_celsius + 11U;
//! ```
//!
//! Confirmed independently against the CERN-OHL-S schematic: TH1/TH2 are
//! `NTCG103JF103FT1` (TDK 10 k, 0402) from `/TMP_10K_A1` and `/TMP_10K_A2` to
//! GND, with R68/R73 (10 k) pulling each node to 3V3, and those nodes land on
//! ESP32 pads 5 and 4 = GPIO5 (ADC1_CH4) and GPIO4 (ADC1_CH3). The firmware's
//! channel mapping agrees exactly: `V_TEMP_10K_A1 -> ADC_CHANNEL_4`,
//! `V_TEMP_10K_A2 -> ADC_CHANNEL_3`.
//!
//! # Three upstream behaviours deliberately not copied
//!
//! 1. **A temperature-typed error sentinel.** `ADC_get_temperature` returns
//!    `-273.15` when the reading is invalid. That is absolute zero expressed as
//!    a normal `float` return: a caller that does not test for it sees an
//!    absurdly COLD reading, which is precisely the direction that silences
//!    thermal protection. We return [`Option`] and have no in-band error value.
//! 2. **No upper bound on the input.** Upstream tests only `voltage <= 0`. At
//!    `voltage >= 3.3` the divider term `(3.3 - voltage)` is zero or negative,
//!    producing `inf`, `NaN`, or a negative resistance whose `ln` is `NaN`. That
//!    is the OPEN-CIRCUIT case — an unplugged or unpopulated thermistor — so it
//!    is exactly the case a safety sensor must not silently mishandle.
//! 3. **An unexplained `+ 11` baked into the physics.** Upstream adds 11 °C to
//!    every result with no derivation. It is not part of the beta equation; it
//!    is a board calibration. We keep the physics pure and carry the offset as a
//!    per-board declared field ([`NtcChannel::offset_c`]) so it is visible,
//!    attributable, and cannot leak onto a board that never measured it.

/// Nominal thermistor resistance at [`T0_KELVIN`], in ohms.
///
/// `#define R0 10000` — and the same value is the divider's pull-up, which is
/// why the ratio `R_t / R0` in the beta equation is dimensionless either way.
pub const R0_OHMS: f32 = 10_000.0;

/// The thermistor's beta constant, in kelvin.
///
/// `#define BETA 3380`. Note this is the VENDOR's figure. The fitted part is a
/// TDK `NTCG103JF103FT1`, whose datasheet B25/85 is commonly quoted as 3435 K;
/// 3380 is the B25/50 figure. We use the vendor's 3380 because it is the number
/// their board was characterized with and the one their `+11` offset was fitted
/// against — mixing a different beta with their offset would compound two
/// calibrations that were never measured together.
pub const BETA_KELVIN: f32 = 3380.0;

/// Reference temperature for [`R0_OHMS`], in kelvin (25 °C).
pub const T0_KELVIN: f32 = 298.15;

/// Absolute zero, in degrees Celsius.
pub const ABSOLUTE_ZERO_C: f32 = -273.15;

/// The divider's top rail, in millivolts.
///
/// This is the RAIL the pull-up returns to (3V3), NOT the ADC's full-scale
/// voltage. They are different numbers on an ESP32-S3: at 12 dB attenuation the
/// converter saturates around 3.1 V, below the rail. Using full-scale here would
/// silently rescale every reading.
pub const VREF_MV: u32 = 3300;

/// Widest temperature this module will report, in degrees Celsius.
///
/// Not a safety clamp — a sanity bound. Anything beyond it means the divider is
/// faulted rather than the board being that temperature. We reject rather than
/// report, EXCEPT above the top bound: see [`celsius_from_millivolts`].
pub const PLAUSIBLE_MIN_C: f32 = -40.0;

/// Top of the plausible band, in degrees Celsius.
pub const PLAUSIBLE_MAX_C: f32 = 150.0;

/// One board-declared NTC channel: which ADC input, and the board's own
/// calibration offset.
///
/// Declared per model by `BitAxeModel::ntc_thermal_channels` so that adding a
/// board with thermistors is a table row rather than another call-site branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtcChannel {
    /// ADC1 channel index (ESP32-S3 `ADC_CHANNEL_n`), e.g. 4 for GPIO5.
    pub adc1_channel: u8,
    /// The GPIO this channel corresponds to. Carried for logging and for the
    /// pin-collision test — the driver selects by channel, not by pin.
    pub gpio: u8,
    /// Board calibration added to the physics result, in degrees Celsius.
    ///
    /// Whole degrees, and signed: this is a measured board offset, and a board
    /// that never measured one declares `0`. Kept OUT of the beta equation on
    /// purpose — see the module docs.
    pub offset_c: i8,
    /// Which ASIC index this thermistor sits next to, for reporting.
    pub asic_index: u8,
}

/// Convert an ADC reading in millivolts to degrees Celsius.
///
/// Returns `None` — never an in-band sentinel — when the input cannot be
/// converted:
///
/// * `mv` is not below [`VREF_MV`]. This is the OPEN-CIRCUIT / missing-
///   thermistor case; upstream divides by zero here.
/// * `mv` is zero. A dead-short reads as infinite temperature; we decline to
///   report a number derived from a divider that is not dividing.
/// * the computed value is not finite, or falls below [`PLAUSIBLE_MIN_C`].
///
/// A result ABOVE [`PLAUSIBLE_MAX_C`] is returned clamped to that bound rather
/// than discarded, because discarding it would throw away an over-temperature
/// signal — the one reading a thermal supervisor most needs to see. Under-
/// reporting is the only direction that can hurt, so the hot end fails loud and
/// the cold end fails silent.
///
/// # On the layering
///
/// The open-circuit case is rejected at THREE independent points: the `mv >=
/// VREF_MV` bound here, the `resistance` finite/positive check, and the
/// `ln_ratio` finite check. Mutation testing showed none of them is individually
/// necessary — deleting the first two still yields `None`, because `ln(inf)` is
/// `inf` and `ln(negative)` is `NaN`, so the innermost check catches it anyway.
/// That is deliberate redundancy, not dead code, and it is recorded here so
/// nobody reads the early bound as the single thing standing between this board
/// and a divide-by-zero. The real guarantee is the exhaustive-input test
/// (`every_input_is_either_plausible_or_refused`), which asserts the END-TO-END
/// property over every input rather than trusting any one guard.
pub fn celsius_from_millivolts(mv: u32, offset_c: i8) -> Option<f32> {
    if mv == 0 || mv >= VREF_MV {
        return None;
    }
    let v = mv as f32;
    let vref = VREF_MV as f32;

    // R_t = R0 * (V / (VREF - V)). `VREF - V` is strictly positive here.
    let resistance = R0_OHMS * (v / (vref - v));
    if !resistance.is_finite() || resistance <= 0.0 {
        return None;
    }

    // 1/T = 1/T0 + (1/BETA) * ln(R_t / R0), rearranged as upstream writes it.
    let ln_ratio = libm_ln(resistance / R0_OHMS);
    if !ln_ratio.is_finite() {
        return None;
    }
    let denom = ln_ratio + (BETA_KELVIN / T0_KELVIN);
    if !denom.is_finite() || denom == 0.0 {
        return None;
    }
    let kelvin = BETA_KELVIN / denom;
    if !kelvin.is_finite() {
        return None;
    }

    let celsius = kelvin + ABSOLUTE_ZERO_C + offset_c as f32;
    if !celsius.is_finite() || celsius < PLAUSIBLE_MIN_C {
        return None;
    }
    Some(celsius.min(PLAUSIBLE_MAX_C))
}

/// Natural log.
///
/// `f32::ln` is in `std`, which this crate has on both the host and ESP-IDF
/// targets, so this is a thin alias kept as a single named seam rather than a
/// reimplementation — if this module is ever needed in a `no_std` context, only
/// this function changes.
#[inline]
fn libm_ln(x: f32) -> f32 {
    x.ln()
}

/// The hottest valid reading across a set of channels, with each channel's own
/// offset applied.
///
/// Hottest rather than mean: this feeds a thermal supervisor, and on a
/// multi-die board the die that is about to cook is the one that matters. Same
/// rule the Hex TMP1075 path already applies (`a.max(b)`). Channels that fail
/// to convert are skipped, so one faulted thermistor does not blind the other.
pub fn hottest(readings: &[(NtcChannel, u32)]) -> Option<f32> {
    let mut best: Option<f32> = None;
    for (chan, mv) in readings {
        if let Some(c) = celsius_from_millivolts(*mv, chan.offset_c) {
            best = Some(match best {
                Some(b) if b >= c => b,
                _ => c,
            });
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The BitForge Nano's two channels, as the board declares them.
    const A1: NtcChannel = NtcChannel {
        adc1_channel: 4,
        gpio: 5,
        offset_c: 11,
        asic_index: 0,
    };
    const A2: NtcChannel = NtcChannel {
        adc1_channel: 3,
        gpio: 4,
        offset_c: 11,
        asic_index: 1,
    };

    /// At 25 °C the NTC is 10 k, matching the 10 k pull-up, so the divider sits
    /// at exactly half the rail. That is the one point the physics can be
    /// checked against by hand with no datasheet.
    #[test]
    fn half_rail_is_the_reference_temperature() {
        let t = celsius_from_millivolts(VREF_MV / 2, 0).expect("mid-rail converts");
        assert!(
            (t - 25.0).abs() < 0.5,
            "half rail must be ~25 C (R_t == R0), got {t}"
        );
    }

    /// The board offset is additive and lives outside the physics.
    #[test]
    fn the_board_offset_is_applied_on_top_of_the_physics() {
        let bare = celsius_from_millivolts(VREF_MV / 2, 0).unwrap();
        let with_offset = celsius_from_millivolts(VREF_MV / 2, 11).unwrap();
        assert!(
            (with_offset - bare - 11.0).abs() < 0.01,
            "offset must be a pure addition: {bare} vs {with_offset}"
        );
    }

    /// Falling voltage must mean rising temperature. This is the sign of the
    /// whole sensor: get it backwards and the supervisor cools when it should
    /// throttle.
    #[test]
    fn lower_voltage_reads_hotter() {
        let cool = celsius_from_millivolts(2000, 0).unwrap();
        let mid = celsius_from_millivolts(1650, 0).unwrap();
        let hot = celsius_from_millivolts(600, 0).unwrap();
        assert!(
            cool < mid && mid < hot,
            "monotonicity broken: {cool} / {mid} / {hot}"
        );
    }

    /// The open-circuit case upstream divides by zero on.
    #[test]
    fn an_open_circuit_is_refused_not_divided_by_zero() {
        assert_eq!(celsius_from_millivolts(VREF_MV, 0), None);
        assert_eq!(celsius_from_millivolts(VREF_MV + 1, 0), None);
        assert_eq!(celsius_from_millivolts(u32::MAX, 0), None);
    }

    /// A zero reading is refused rather than reported as infinitely hot.
    #[test]
    fn a_dead_short_is_refused() {
        assert_eq!(celsius_from_millivolts(0, 0), None);
    }

    /// There must be no in-band error value. Upstream returns -273.15, which a
    /// careless caller reads as a very cold — and therefore very safe — board.
    #[test]
    fn no_reading_can_ever_be_the_upstream_error_sentinel() {
        for mv in 0..=VREF_MV + 50 {
            if let Some(t) = celsius_from_millivolts(mv, 0) {
                assert!(
                    t > PLAUSIBLE_MIN_C - 0.001,
                    "mv={mv} produced {t}, at/below the implausible floor"
                );
                assert!(
                    (t - ABSOLUTE_ZERO_C).abs() > 1.0,
                    "mv={mv} reproduced the upstream -273.15 sentinel as a real reading"
                );
            }
        }
    }

    /// Every representable input either converts to a finite, plausible number
    /// or is refused. Nothing in between.
    #[test]
    fn every_input_is_either_plausible_or_refused() {
        for mv in 0..=(VREF_MV + 200) {
            match celsius_from_millivolts(mv, 11) {
                Some(t) => {
                    assert!(t.is_finite(), "mv={mv} produced non-finite {t}");
                    assert!(
                        (PLAUSIBLE_MIN_C..=PLAUSIBLE_MAX_C).contains(&t),
                        "mv={mv} produced out-of-band {t}"
                    );
                }
                None => {}
            }
        }
    }

    /// An over-temperature reading must SURVIVE, clamped, rather than be
    /// discarded — it is the reading the supervisor most needs.
    #[test]
    fn the_hot_end_is_clamped_not_discarded() {
        // A near-short reads as extremely hot.
        let t = celsius_from_millivolts(1, 0).expect("a hot reading must survive");
        assert_eq!(t, PLAUSIBLE_MAX_C);
    }

    /// The hottest channel wins, and one faulted thermistor does not blind the
    /// other.
    #[test]
    fn hottest_takes_the_max_and_tolerates_a_faulted_channel() {
        let cooler = 2000;
        let hotter = 900;
        let both = hottest(&[(A1, cooler), (A2, hotter)]).unwrap();
        let just_hot = celsius_from_millivolts(hotter, A2.offset_c).unwrap();
        assert!((both - just_hot).abs() < 0.01, "max not taken: {both}");

        // One channel open-circuit: the other still reports.
        let one_dead = hottest(&[(A1, VREF_MV), (A2, hotter)]).unwrap();
        assert!((one_dead - just_hot).abs() < 0.01);

        // Both dead: no reading at all, rather than a fabricated one.
        assert_eq!(hottest(&[(A1, VREF_MV), (A2, 0)]), None);
        assert_eq!(hottest(&[]), None);
    }

    /// The two BitForge channels are distinct inputs. A copy-paste that pointed
    /// both at one ADC channel would report one die's temperature twice and
    /// silently lose the other.
    #[test]
    fn the_two_bitforge_channels_are_distinct() {
        assert_ne!(A1.adc1_channel, A2.adc1_channel);
        assert_ne!(A1.gpio, A2.gpio);
        assert_ne!(A1.asic_index, A2.asic_index);
        // Netlist: GPIO5 = ADC1_CH4 (A1), GPIO4 = ADC1_CH3 (A2). The firmware's
        // own mapping agrees: V_TEMP_10K_A1 -> ADC_CHANNEL_4.
        assert_eq!((A1.gpio, A1.adc1_channel), (5, 4));
        assert_eq!((A2.gpio, A2.adc1_channel), (4, 3));
    }
}
