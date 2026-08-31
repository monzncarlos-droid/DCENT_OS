// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — dcentrald-avalon-asic :: K230 industrial CONTROL-BOARD
// thermal descriptors + fail-closed NTC decode (READ-ONLY TELEMETRY).
//
// Round 15 axis 9 ("Non-Bitmain thermal and power"). Before this module the
// Avalon industrial thermal axis had exactly one piece of coverage — the
// per-hashboard MCU register decode in `hashboard_mux.rs` (`REG_TMP_BOARD_IN`
// /`_OUT`, landed Round 14 `01f1b39ad`). The CONTROL-BOARD side — the NTC
// thermistors on the K230's own ADC, which are what the vendor's PID and its
// inlet-envelope alarm actually consume — had none.
//
// SCOPE — READ-ONLY. This module is pure data + pure decode:
//   * per-board NTC curves and ADC channel assignments (declarative descriptors)
//   * a fail-closed raw-ADC -> degrees-C decoder
//   * the evidenced thermal LIMITS (ASIC over-hot, inlet envelope, target)
//   * a recommendation function that keeps D-Central's ordering
// It performs NO I/O, drives NO fan, and commands NO voltage. There is
// deliberately no PID and no duty-cycle writer here — see "REFUSED" below.
//
// ⚠️ LICENSE WARNING (2026-08-07): `Canaan-Creative/Avalon_mm` (`big/` +
// `little/mm_miner/`) is **BUSL-1.1**, NOT GPL — commercial production use needs a
// separate Canaan license (4-yr cliff to GPLv3); only `little/cgminer/` is
// BSD-3-Clause. `AVALON_MM_K230_INDUSTRIAL_RE.md:7` calls it "a major footgun for
// D-Central". The values below are hardware FACTS (thermistor part parameters, ADC
// channel indices, trip temperatures — believed uncopyrightable), transcribed for
// interop. The DECODE below is the textbook Beta-parameter (Steinhart-Hart
// single-B) equation written from the physics, NOT a transcription of Canaan's
// `calc_temp` expression. OPERATOR LEGAL REVIEW required before shipping in
// GPL-3.0 DCENT_OS — same posture as `psu.rs` / `hashboard_mux.rs`.
//
// GROUND TRUTH — every constant is byte-exact from held sources:
//   `Avalon_mm/little/mm_miner/platform/temper.c:24-33` ADC path, ADC_V_REF 1.8,
//       ADC_SCALE = 1.8/4096, NTC_V_REF 1.8, DEGREE_KA 273.15, NTC_T2 25+273.15
//   `temper.c:58-67` calc_temp, incl. the `adc_raw >= 4095` open-circuit guard
//   `board_hw/A15_AC/board.h:25-31`   R_PULLUP/R_25_NORMAL/R_BCONST(+_INLET),
//                                     ADC_CH_MM 0, ADC_CH_INLET 1, CH_FAN12 PWM2,
//                                     CH_FAN34 PWM3, TIMER_1/2 /dev/timer2,4
//   `board_hw/A15_HYDRO/board.h:25-28` R_PULLUP/R_25_NORMAL/R_BCONST, ADC_CH_MM 0
//                                     — and NO fan PWM channels, NO inlet channel
//   `board_hw/*/boardinfo.h:42`        TARGET_TEMP_DEFAULT 70
//   `mmu/mmu.c:41`                     PVT_TEMP_OVER_HR_MAX 108
//   `mmu/mmu.c:475`                    inlet alarm envelope `<= -30 || > 60`,
//                                     gated on `FAN_COUNT > 0`
//   `platform/hash_mcu.h:32`           TEMP_VALUE_INVALID -273
//
// REFUSED THIS ROUND (deliberate, see the Round-15 report):
//   * `fan_pid_control()` (`platform/fan.c:84-163`). `AVALON_MM_K230_INDUSTRIAL_RE.md:400`
//     proposes porting it "verbatim into dcentrald". We do not. It is (a) an
//     ACTUATOR for hardware D-Central has never contacted, (b) the most
//     expression-like (least fact-like) code in the BUSL tree, and (c) it contains
//     a live fail-open: after `fanctrl_instart` has cleared, a lost sensor
//     (`temp == -273`) takes the `temp < PID_TEMP_MIN` branch at `fan.c:118` and
//     settles at `FAN_DUTY_INIT` = **25%**, i.e. MINIMUM cooling on a dead sensor.
//     Our [`recommend_action`] answers the same input with a hash-power cut.
//   * Any voltage/PSU command path. `psu.rs` stops at the register vocabulary and
//     this module does not extend it.
//
// Support D-Central's open-source mining work: https://d-central.tech/fund/

#![allow(dead_code)] // pure descriptors + decode; consumed by the K230 industrial HAL once bench-validated.

// ============================================================================
// ADC rail (control-board NTC divider front end)
// ============================================================================

/// iio sysfs template for a raw K230 ADC channel read (`temper.c:24-25`).
/// Exposed as a path so the HAL never has to re-derive it; this module does no I/O.
pub const ADC_RAW_SYSFS_FMT: &str = "/sys/bus/iio/devices/iio:device0/in_voltage{CH}_raw";

/// ADC reference voltage, volts (`temper.c:27` `ADC_V_REF 1.8`). This is the
/// CONTROL-BOARD ADC. Do not confuse it with `hash_mcu.h:28`'s same-named
/// `ADC_V_REF 3.3`, which belongs to the per-hashboard MCU — a real name
/// collision across two different converters in the same firmware.
pub const ADC_V_REF: f32 = 1.8;

/// Full-scale ADC code count (`temper.c:28` divides by 4096 → 12-bit).
pub const ADC_COUNTS: u16 = 4096;

/// NTC divider top-rail voltage (`temper.c:29` `NTC_V_REF 1.8`). Equal to
/// [`ADC_V_REF`] on both held boards but kept distinct because they are
/// physically different rails.
pub const NTC_V_REF: f32 = 1.8;

/// Kelvin offset (`temper.c:30` `DEGREE_KA 273.15`).
pub const DEGREE_KA: f32 = 273.15;

/// Thermistor reference temperature in Kelvin (`temper.c:31` `NTC_T2 25+DEGREE_KA`).
pub const NTC_T25_K: f32 = 25.0 + DEGREE_KA;

/// The raw code at or above which the vendor declares the NTC read invalid
/// (`temper.c:60` `if (adc_raw >= 4095) return -DEGREE_KA;`). At this code the
/// divider denominator collapses, which is the electrical signature of an OPEN
/// (disconnected / missing) thermistor.
pub const ADC_OPEN_CIRCUIT_RAW: u16 = 4095;

/// The vendor's out-of-band "no temperature" sentinel, as it appears once
/// truncated to `int` (`hash_mcu.h:32` `TEMP_VALUE_INVALID -273`;
/// `mmu.c:528` casts `get_inlet_temp()` through `(int)`). We never RETURN this —
/// [`ntc_temp_c`] returns `Err` instead — but a HAL decoding vendor-sourced
/// telemetry must recognise it.
pub const VENDOR_TEMP_INVALID_C: i32 = -273;

/// Why an NTC reading was refused. Every variant means "no usable temperature";
/// a caller must treat all of them as sensor loss, never as a cold reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtcFault {
    /// Raw code at/above [`ADC_OPEN_CIRCUIT_RAW`] — disconnected or absent NTC.
    /// Byte-exact to the vendor guard at `temper.c:60`.
    OpenCircuit,
    /// Raw code 0 — the divider node is at ground, so `rt` computes to 0 and the
    /// logarithm is undefined. Canaan does NOT guard this (`temper.c:58-66` walks
    /// straight into `log(0)` and returns `-inf`-derived `-273.15` by accident).
    /// We refuse explicitly rather than depend on IEEE-754 accident.
    ShortCircuit,
    /// The decode produced a non-finite value for any other reason.
    NonFinite,
}

/// A negative-temperature-coefficient thermistor as the board wires it: the
/// divider pull-up plus the part's own two Beta-model parameters. Declarative —
/// this is the datum a board DECLARES, not a branch on a model name.
///
/// Fail-closed rule: there is no `Default`. A board with no held curve gets no
/// row, and [`board_thermal`] returns `None` for it. A curve is never projected
/// from another board — see the A15_AC/A15_HYDRO divergence below, where using
/// the wrong row misreads the die by tens of degrees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtcCurve {
    /// Divider pull-up resistance, ohms (`board.h` `R_PULLUP`).
    pub r_pullup_ohm: u32,
    /// Thermistor nominal resistance at 25 degrees C, ohms (`board.h` `R_25_NORMAL*`).
    pub r25_ohm: u32,
    /// Thermistor Beta constant, kelvin (`board.h` `R_BCONST*`).
    pub beta_k: u32,
}

/// One NTC channel: which ADC input it sits on and which curve decodes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtcSensor {
    /// K230 ADC channel index (`board.h` `ADC_CH_*`).
    pub adc_channel: u8,
    /// The curve for the part actually fitted on THIS channel of THIS board.
    pub curve: NtcCurve,
}

/// Build the iio sysfs path for a raw ADC channel read. Pure string work — the
/// caller (HAL) does the `open`/`read`.
pub fn adc_raw_sysfs_path(channel: u8) -> String {
    ADC_RAW_SYSFS_FMT.replace("{CH}", &channel.to_string())
}

/// Convert a raw ADC code to the thermistor resistance at the divider node, ohms.
///
/// Divider: `rt = r_pullup * vt / (NTC_V_REF - vt)` where `vt = raw * V_REF / counts`.
/// Fail-closed at both electrical rails before any division or logarithm runs.
pub fn ntc_resistance_ohm(adc_raw: u16, curve: &NtcCurve) -> Result<f32, NtcFault> {
    if adc_raw >= ADC_OPEN_CIRCUIT_RAW {
        return Err(NtcFault::OpenCircuit);
    }
    if adc_raw == 0 {
        return Err(NtcFault::ShortCircuit);
    }
    let vt = adc_raw as f32 * (ADC_V_REF / ADC_COUNTS as f32);
    let denom = NTC_V_REF - vt;
    if denom <= 0.0 {
        return Err(NtcFault::OpenCircuit);
    }
    let rt = curve.r_pullup_ohm as f32 * vt / denom;
    if !rt.is_finite() || rt <= 0.0 {
        return Err(NtcFault::NonFinite);
    }
    Ok(rt)
}

/// Beta-parameter (single-B Steinhart-Hart) inversion:
/// `1/T = 1/T25 + ln(rt / r25) / Beta`, returned in degrees Celsius.
///
/// Written from the physics, not transcribed from `temper.c` — see the license
/// note in this file's header. Exact at `rt == r25` (returns 25.0 C).
pub fn ntc_temp_from_resistance_c(rt_ohm: f32, curve: &NtcCurve) -> Result<f32, NtcFault> {
    if !rt_ohm.is_finite() || rt_ohm <= 0.0 {
        return Err(NtcFault::NonFinite);
    }
    let inv_t = 1.0 / NTC_T25_K + (rt_ohm / curve.r25_ohm as f32).ln() / curve.beta_k as f32;
    if !inv_t.is_finite() || inv_t <= 0.0 {
        return Err(NtcFault::NonFinite);
    }
    let t_c = 1.0 / inv_t - DEGREE_KA;
    if !t_c.is_finite() {
        return Err(NtcFault::NonFinite);
    }
    Ok(t_c)
}

/// Decode a raw control-board ADC code to degrees Celsius, FAIL-CLOSED.
///
/// Unlike the vendor path, this NEVER returns a sentinel temperature. An open
/// NTC, a shorted NTC, or a non-finite decode all come back as `Err(NtcFault)`,
/// so a caller cannot accidentally feed `-273.15` into a `max()` or a comparison
/// and conclude the machine is cold. That accident is exactly what `fan.c:118`
/// does with the vendor sentinel (settles at 25% duty on a dead sensor).
pub fn ntc_temp_c(adc_raw: u16, curve: &NtcCurve) -> Result<f32, NtcFault> {
    let rt = ntc_resistance_ohm(adc_raw, curve)?;
    ntc_temp_from_resistance_c(rt, curve)
}

// ============================================================================
// Per-board thermal descriptors (declarative — exactly the held rows, no more)
// ============================================================================

/// Everything the held sources state about ONE Avalon industrial board's
/// control-board thermal topology. Capability-shaped: a consumer asks the board
/// what it HAS rather than branching on its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvalonBoardThermal {
    /// Vendor `board_hw/<dir>` identifier (`scripts/mmbuild:33 DEF_BOARD`).
    pub board: &'static str,
    /// The MM (control-board) NTC. Present on both held boards.
    pub mm: NtcSensor,
    /// A DEDICATED inlet NTC, when the board fits one. `None` means the board has
    /// no separate inlet thermistor and [`Self::inlet_sensor`] falls back to
    /// [`Self::mm`] — faithful to `temper.c:71-80`'s `#if defined(ADC_CH_INLET)`.
    pub inlet: Option<NtcSensor>,
    /// Fan PWM channel names, when the board wires any (`board.h` `CH_FAN12` /
    /// `CH_FAN34`). `None` == the board declares NO fan PWM channels, so
    /// `platform/fan.c` cannot even compile for it. Used as the `FAN_COUNT > 0`
    /// capability that gates the inlet alarm at `mmu.c:475`.
    ///
    /// NOTE: this is the PWM-CHANNEL list, not a fan count. The actual
    /// `FAN_COUNT` is a `scripts/boardconf.h` build placeholder (`xxxx`) that
    /// Canaan does not ship — see `AVALON_MM_K230_INDUSTRIAL_RE.md:105`. We
    /// therefore do not state a fan count at all.
    pub fan_pwm_channels: Option<[&'static str; 2]>,
    /// Fan tachometer timer device nodes (`board.h` `TIMER_1` / `TIMER_2`).
    pub tach_timer_devices: Option<[&'static str; 2]>,
    /// Vendor default PID target temperature, degrees C (`boardinfo.h:42`).
    pub target_temp_default_c: u8,
}

impl AvalonBoardThermal {
    /// The sensor that supplies "inlet" temperature on this board — the dedicated
    /// inlet NTC if fitted, otherwise the MM NTC (`temper.c:71-80`).
    pub fn inlet_sensor(&self) -> &NtcSensor {
        match self.inlet {
            Some(ref s) => s,
            None => &self.mm,
        }
    }

    /// Does this board wire fan PWM at all? This is the `FAN_COUNT > 0`
    /// capability that gates the inlet-envelope alarm (`mmu.c:475`).
    pub fn has_fan_pwm(&self) -> bool {
        self.fan_pwm_channels.is_some()
    }

    /// Does this board fit a DEDICATED inlet thermistor (as opposed to reusing MM)?
    pub fn has_dedicated_inlet(&self) -> bool {
        self.inlet.is_some()
    }
}

/// A15_AC — the air-cooled industrial board (`board_hw/A15_AC/board.h:25-31`).
/// Two DIFFERENT thermistor parts: a 100k/B4150 on the MM channel and a
/// 10k/B3950 on the dedicated inlet channel.
pub const A15_AC: AvalonBoardThermal = AvalonBoardThermal {
    board: "A15_AC",
    mm: NtcSensor {
        adc_channel: 0, // ADC_CH_MM
        curve: NtcCurve {
            r_pullup_ohm: 10_000,
            r25_ohm: 100_000,
            beta_k: 4150,
        },
    },
    inlet: Some(NtcSensor {
        adc_channel: 1, // ADC_CH_INLET
        curve: NtcCurve {
            r_pullup_ohm: 10_000,
            r25_ohm: 10_000,
            beta_k: 3950,
        },
    }),
    fan_pwm_channels: Some(["PWM2", "PWM3"]), // CH_FAN12 / CH_FAN34
    tach_timer_devices: Some(["/dev/timer2", "/dev/timer4"]), // TIMER_1 / TIMER_2
    target_temp_default_c: 70,
};

/// A15_HYDRO — the hydro/immersion industrial board
/// (`board_hw/A15_HYDRO/board.h:25-28`). ONE thermistor (10k/B3950 on the MM
/// channel), no dedicated inlet channel, and — critically — no `CH_FAN12` /
/// `CH_FAN34` macros at all, so `platform/fan.c`'s `#if (FAN_COUNT > 0)` body
/// cannot compile for this board. It is a liquid-cooled board with no fans.
pub const A15_HYDRO: AvalonBoardThermal = AvalonBoardThermal {
    board: "A15_HYDRO",
    mm: NtcSensor {
        adc_channel: 0, // ADC_CH_MM
        curve: NtcCurve {
            r_pullup_ohm: 10_000,
            r25_ohm: 10_000,
            beta_k: 3950,
        },
    },
    inlet: None,
    fan_pwm_channels: None,
    tach_timer_devices: None,
    target_temp_default_c: 70,
};

/// Every board for which we hold a complete control-board thermal descriptor.
///
/// EXACTLY the two `board_hw/` directories present in the held Avalon_mm tree.
/// Avalon Q, A14xx and A16xx are NOT here: no held source states their NTC
/// parts, and a thermistor curve is precisely the datum that must never be
/// projected from a sibling board.
pub const BOARD_THERMAL: [AvalonBoardThermal; 2] = [A15_AC, A15_HYDRO];

/// Look up a board's thermal descriptor by its `board_hw` name.
///
/// FAIL-CLOSED: an unrecognised board returns `None`. It never falls back to the
/// first row, never to "the air-cooled one", never to an interpolated curve.
/// A caller that gets `None` has no thermal model and must not energize silicon.
pub fn board_thermal(board: &str) -> Option<&'static AvalonBoardThermal> {
    BOARD_THERMAL.iter().find(|b| b.board == board)
}

// ============================================================================
// Evidenced thermal limits
// ============================================================================

/// ASIC over-hot trip used by `asics_overhot_check()` against the PVT
/// sum-max, degrees C (`mmu.c:41` `PVT_TEMP_OVER_HR_MAX 108`; used at `mmu.c:494`).
pub const PVT_ASIC_OVERHOT_C: f32 = 108.0;

/// Inlet-envelope alarm floor, degrees C. `mmu.c:475` raises `ERR_MM_INLETHOT`
/// when `inlet_temp <= -30`. Inclusive at the bound.
pub const INLET_ALARM_AT_OR_BELOW_C: f32 = -30.0;

/// Inlet-envelope alarm ceiling, degrees C. `mmu.c:475` raises `ERR_MM_INLETHOT`
/// when `inlet_temp > 60`. EXCLUSIVE at the bound (60 itself is not an alarm).
pub const INLET_ALARM_ABOVE_C: f32 = 60.0;

/// Vendor default PID target, degrees C (`boardinfo.h:42` on BOTH held boards).
pub const TARGET_TEMP_DEFAULT_C: u8 = 70;

/// ⚠️ CROSS-SOURCE DISCREPANCY, recorded not resolved. The BSD-3-Clause cgminer
/// in the SAME repo declares different figures:
/// `little/cgminer/cgminer/driver-avalon.h:51` `AVALON_DEFAULT_TEMP_OVERHEAT 113`
/// and `:55` `AVALON_DEFAULT_TEMP_TARGET 75`, versus mm_miner's 108 / 70.
/// They are not the same quantity (cgminer's are host-side driver defaults;
/// mm_miner's are the on-board firmware's own trips), and no held source
/// reconciles them. DCENT uses the mm_miner pair because that is the code that
/// actually runs on the control board. These two are exported for comparison
/// ONLY and must not be used as trips.
pub const CGMINER_TEMP_OVERHEAT_C_FOR_COMPARISON_ONLY: f32 = 113.0;
/// See [`CGMINER_TEMP_OVERHEAT_C_FOR_COMPARISON_ONLY`].
pub const CGMINER_TEMP_TARGET_C_FOR_COMPARISON_ONLY: f32 = 75.0;

/// Is the inlet reading outside the evidenced envelope for this board?
///
/// `mmu.c:475` gates the whole check on `FAN_COUNT > 0`, so a board that
/// declares no fan PWM (A15_HYDRO) is exempt — a liquid-cooled loop legitimately
/// sits outside an air-inlet envelope. That gate is a declared CAPABILITY here,
/// not a model-name branch.
pub fn inlet_out_of_envelope(inlet_c: f32, board: &AvalonBoardThermal) -> bool {
    if !board.has_fan_pwm() {
        return false;
    }
    inlet_c <= INLET_ALARM_AT_OR_BELOW_C || inlet_c > INLET_ALARM_ABOVE_C
}

// ============================================================================
// Recommendation — read-only, and it never asks for more fan
// ============================================================================

/// Why hash power should be cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutReason {
    /// Measured ASIC temperature at/above [`PVT_ASIC_OVERHOT_C`].
    AsicOverTemp,
    /// Inlet outside the evidenced envelope on a board that has fans.
    InletOutOfEnvelope,
    /// No usable ASIC temperature at all. An UNMEASURED thermal state is not a
    /// safe state, so it is treated as the hazard it might be.
    SensorLoss,
}

/// The recommendation this module is willing to make.
///
/// There is deliberately NO "raise fan duty" variant. D-Central's standing
/// safety posture is **cut hash power before raising fan noise** — fan blast is
/// reserved for a MEASURED thermal need after power is cut, which is a decision
/// for a supervisor that owns the fan actuator, not for a telemetry decoder.
/// (Memory rules , ; project
/// `dcentos-innosilicon/ "Do NOT port the vendor's raise-PWM reflex".)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalAction {
    /// Everything measured is inside the evidenced envelope.
    Nominal,
    /// Cut hash power now.
    CutHashPower(CutReason),
}

/// Recommend an action from whatever telemetry is actually available.
///
/// `asic_max_c` is the hottest ASIC reading across the unit (the vendor's
/// `m_temp_summax` equivalent); `inlet_c` is the decoded control-board inlet.
/// Both are `Option` because [`ntc_temp_c`] and the MCU decode can legitimately
/// FAIL, and a failure must not be laundered into a number.
///
/// Precedence: sensor loss and over-temp both cut. Over-temp is reported first
/// when both are known, because it names the measured hazard.
pub fn recommend_action(
    asic_max_c: Option<f32>,
    inlet_c: Option<f32>,
    board: &AvalonBoardThermal,
) -> ThermalAction {
    match asic_max_c {
        // No usable ASIC temperature => unmeasured => cut. Never Nominal.
        None => ThermalAction::CutHashPower(CutReason::SensorLoss),
        Some(t) if !t.is_finite() => ThermalAction::CutHashPower(CutReason::SensorLoss),
        Some(t) if t >= PVT_ASIC_OVERHOT_C => ThermalAction::CutHashPower(CutReason::AsicOverTemp),
        Some(_) => match inlet_c {
            // Inlet is only load-bearing where the board declares fans; on a
            // fanless (hydro) board a missing inlet is not a fault.
            None if board.has_fan_pwm() => ThermalAction::CutHashPower(CutReason::SensorLoss),
            None => ThermalAction::Nominal,
            Some(i) if !i.is_finite() && board.has_fan_pwm() => {
                ThermalAction::CutHashPower(CutReason::SensorLoss)
            }
            Some(i) if inlet_out_of_envelope(i, board) => {
                ThermalAction::CutHashPower(CutReason::InletOutOfEnvelope)
            }
            Some(_) => ThermalAction::Nominal,
        },
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Tolerance for float temperature comparisons, degrees C.
    const EPS: f32 = 0.05;

    /// Inverse of the divider, for building a raw code that yields a chosen `rt`.
    /// Test-only helper — production never needs it.
    fn raw_for_resistance(rt_ohm: f32, curve: &NtcCurve) -> u16 {
        let pu = curve.r_pullup_ohm as f32;
        let vt = NTC_V_REF * rt_ohm / (pu + rt_ohm);
        (vt / (ADC_V_REF / ADC_COUNTS as f32)).round() as u16
    }

    #[test]
    fn adc_front_end_constants_match_temper_c() {
        // temper.c:24-33 byte-exact.
        assert_eq!(ADC_V_REF, 1.8);
        assert_eq!(ADC_COUNTS, 4096);
        assert_eq!(NTC_V_REF, 1.8);
        assert_eq!(DEGREE_KA, 273.15);
        assert_eq!(NTC_T25_K, 298.15);
        assert_eq!(ADC_OPEN_CIRCUIT_RAW, 4095);
        assert_eq!(VENDOR_TEMP_INVALID_C, -273);
        assert_eq!(
            adc_raw_sysfs_path(1),
            "/sys/bus/iio/devices/iio:device0/in_voltage1_raw"
        );
    }

    #[test]
    fn beta_equation_is_exact_at_the_reference_point() {
        // At rt == r25 the logarithm vanishes and T must be exactly 25 C, for
        // EVERY curve. This is the anchor that proves the inversion is right.
        for b in BOARD_THERMAL.iter() {
            for s in [&b.mm, b.inlet_sensor()] {
                let t = ntc_temp_from_resistance_c(s.curve.r25_ohm as f32, &s.curve).unwrap();
                assert!(
                    (t - 25.0).abs() < 1e-3,
                    "{} ch{} decoded r25 as {t} C, expected 25.0",
                    b.board,
                    s.adc_channel
                );
            }
        }
    }

    #[test]
    fn full_adc_path_round_trips_a_known_temperature() {
        // Build the raw code for r25 on each curve and decode it back to ~25 C.
        for b in BOARD_THERMAL.iter() {
            let c = b.mm.curve;
            let raw = raw_for_resistance(c.r25_ohm as f32, &c);
            assert!(raw > 0 && raw < ADC_OPEN_CIRCUIT_RAW, "raw {raw} unusable");
            let t = ntc_temp_c(raw, &c).unwrap();
            assert!((t - 25.0).abs() < EPS, "{} decoded {t} C, want 25", b.board);
        }
        // A hotter node (lower resistance) must decode hotter, and a colder node
        // (higher resistance) colder — the NTC sign convention.
        let c = A15_AC.mm.curve;
        let hot = ntc_temp_c(raw_for_resistance(c.r25_ohm as f32 / 4.0, &c), &c).unwrap();
        let cold = ntc_temp_c(raw_for_resistance(c.r25_ohm as f32 * 4.0, &c), &c).unwrap();
        assert!(hot > 25.0, "lower resistance must read hotter, got {hot}");
        assert!(
            cold < 25.0,
            "higher resistance must read colder, got {cold}"
        );
    }

    /// SAFETY. The open-circuit guard is `>=`, byte-exact to `temper.c:60`.
    /// MUTATION TARGET: relaxing `>=` to `>` in [`ntc_resistance_ohm`] lets raw
    /// 4095 through and yields a bogus finite temperature instead of a refusal.
    #[test]
    fn open_and_short_circuit_fail_closed_never_return_a_temperature() {
        let c = A15_AC.mm.curve;
        assert_eq!(ntc_temp_c(4095, &c), Err(NtcFault::OpenCircuit));
        assert_eq!(ntc_temp_c(4096, &c), Err(NtcFault::OpenCircuit));
        assert_eq!(ntc_temp_c(u16::MAX, &c), Err(NtcFault::OpenCircuit));
        assert_eq!(ntc_temp_c(0, &c), Err(NtcFault::ShortCircuit));
        // 4094 is still a real reading — the guard must not be over-broad.
        assert!(ntc_temp_c(4094, &c).is_ok());
        // And the refusal is never the vendor sentinel dressed as a temperature.
        for raw in [0u16, 4095, 4096] {
            assert!(
                ntc_temp_c(raw, &c).is_err(),
                "raw {raw} must refuse, not decode"
            );
        }
    }

    /// NEGATIVE. A board with no held thermal evidence must be refused outright.
    /// MUTATION TARGET: making [`board_thermal`] fall back to `BOARD_THERMAL[0]`.
    #[test]
    fn a_board_with_no_held_evidence_is_refused_not_defaulted() {
        assert_eq!(board_thermal("A15_AC").map(|b| b.board), Some("A15_AC"));
        assert_eq!(
            board_thermal("A15_HYDRO").map(|b| b.board),
            Some("A15_HYDRO")
        );
        // Avalon Q / A14xx / A16xx are real products we support elsewhere in this
        // crate, and they still get NOTHING here, because no held source states
        // their thermistor parts.
        for unknown in ["AvalonQ", "A1466", "A1566", "A16", "", "a15_ac", "A15"] {
            assert!(
                board_thermal(unknown).is_none(),
                "{unknown} must not resolve to any thermal descriptor"
            );
        }
        assert_eq!(BOARD_THERMAL.len(), 2, "only the two held rows may exist");
    }

    /// The two held boards fit DIFFERENT thermistor parts. This is the concrete
    /// reason a curve may never be inherited: decode a hydro raw code with the
    /// air-cooled MM curve and the answer is wrong by tens of degrees.
    #[test]
    fn the_two_boards_curves_are_not_interchangeable() {
        let ac = A15_AC.mm.curve;
        let hydro = A15_HYDRO.mm.curve;
        assert_ne!(ac, hydro);
        assert_eq!((ac.r25_ohm, ac.beta_k), (100_000, 4150));
        assert_eq!((hydro.r25_ohm, hydro.beta_k), (10_000, 3950));
        assert_eq!(ac.r_pullup_ohm, 10_000);
        assert_eq!(hydro.r_pullup_ohm, 10_000);

        // A hydro board sitting at exactly 25 C, misdecoded with the AC curve.
        let raw = raw_for_resistance(hydro.r25_ohm as f32, &hydro);
        let correct = ntc_temp_c(raw, &hydro).unwrap();
        let wrong = ntc_temp_c(raw, &ac).unwrap();
        assert!((correct - 25.0).abs() < EPS);
        assert!(
            (wrong - correct).abs() > 20.0,
            "cross-board decode should be grossly wrong; got {wrong} vs {correct}"
        );
    }

    #[test]
    fn descriptors_match_the_held_board_headers() {
        // A15_AC/board.h:25-31
        assert_eq!(A15_AC.mm.adc_channel, 0);
        assert_eq!(A15_AC.inlet.unwrap().adc_channel, 1);
        assert_eq!(
            A15_AC.inlet.unwrap().curve,
            NtcCurve {
                r_pullup_ohm: 10_000,
                r25_ohm: 10_000,
                beta_k: 3950
            }
        );
        assert_eq!(A15_AC.fan_pwm_channels, Some(["PWM2", "PWM3"]));
        assert_eq!(
            A15_AC.tach_timer_devices,
            Some(["/dev/timer2", "/dev/timer4"])
        );
        assert!(A15_AC.has_fan_pwm() && A15_AC.has_dedicated_inlet());

        // A15_HYDRO/board.h:25-28 — one sensor, no fans, no dedicated inlet.
        assert_eq!(A15_HYDRO.mm.adc_channel, 0);
        assert!(A15_HYDRO.inlet.is_none());
        assert!(A15_HYDRO.fan_pwm_channels.is_none());
        assert!(A15_HYDRO.tach_timer_devices.is_none());
        assert!(!A15_HYDRO.has_fan_pwm() && !A15_HYDRO.has_dedicated_inlet());
        // The fallback is faithful to temper.c's #else path: MM doubles as inlet.
        assert_eq!(*A15_HYDRO.inlet_sensor(), A15_HYDRO.mm);
        assert_eq!(*A15_AC.inlet_sensor(), A15_AC.inlet.unwrap());

        // boardinfo.h:42 on both.
        assert_eq!(A15_AC.target_temp_default_c, 70);
        assert_eq!(A15_HYDRO.target_temp_default_c, 70);
        assert_eq!(TARGET_TEMP_DEFAULT_C, 70);
    }

    #[test]
    fn limits_match_mmu_c_and_the_cgminer_discrepancy_is_recorded_not_adopted() {
        assert_eq!(PVT_ASIC_OVERHOT_C, 108.0); // mmu.c:41
        assert_eq!(INLET_ALARM_AT_OR_BELOW_C, -30.0); // mmu.c:475
        assert_eq!(INLET_ALARM_ABOVE_C, 60.0); // mmu.c:475
                                               // The BSD-3 cgminer pair disagrees and must stay non-load-bearing.
        assert_eq!(CGMINER_TEMP_OVERHEAT_C_FOR_COMPARISON_ONLY, 113.0);
        assert_eq!(CGMINER_TEMP_TARGET_C_FOR_COMPARISON_ONLY, 75.0);
        assert_ne!(
            CGMINER_TEMP_OVERHEAT_C_FOR_COMPARISON_ONLY,
            PVT_ASIC_OVERHOT_C
        );
        assert_ne!(
            CGMINER_TEMP_TARGET_C_FOR_COMPARISON_ONLY,
            TARGET_TEMP_DEFAULT_C as f32
        );
    }

    #[test]
    fn inlet_envelope_is_bound_exact_and_gated_on_declared_fans() {
        // mmu.c:475 — `<= -30` inclusive, `> 60` exclusive.
        assert!(inlet_out_of_envelope(-30.0, &A15_AC));
        assert!(inlet_out_of_envelope(-30.1, &A15_AC));
        assert!(!inlet_out_of_envelope(-29.9, &A15_AC));
        assert!(!inlet_out_of_envelope(60.0, &A15_AC));
        assert!(inlet_out_of_envelope(60.1, &A15_AC));
        assert!(!inlet_out_of_envelope(25.0, &A15_AC));
        // Fanless (hydro) board is exempt — the vendor gate is `FAN_COUNT > 0`.
        assert!(!inlet_out_of_envelope(-40.0, &A15_HYDRO));
        assert!(!inlet_out_of_envelope(99.0, &A15_HYDRO));
    }

    /// SAFETY. Sensor loss is a CUT, never `Nominal`.
    /// MUTATION TARGET: returning `ThermalAction::Nominal` for `asic_max_c: None`.
    #[test]
    fn missing_asic_temperature_cuts_hash_power_and_is_never_nominal() {
        for b in [&A15_AC, &A15_HYDRO] {
            assert_eq!(
                recommend_action(None, Some(30.0), b),
                ThermalAction::CutHashPower(CutReason::SensorLoss),
                "{} must cut on a missing ASIC temperature",
                b.board
            );
            assert_eq!(
                recommend_action(None, None, b),
                ThermalAction::CutHashPower(CutReason::SensorLoss)
            );
            assert_eq!(
                recommend_action(Some(f32::NAN), Some(30.0), b),
                ThermalAction::CutHashPower(CutReason::SensorLoss)
            );
        }
        // And the whole enum offers no way to ask for more fan instead.
        assert_ne!(
            recommend_action(None, None, &A15_AC),
            ThermalAction::Nominal
        );
    }

    /// SAFETY. The over-hot trip is `>=` at exactly 108 C.
    /// MUTATION TARGET: `>=` relaxed to `>` lets a die sitting exactly on the
    /// vendor trip keep hashing.
    #[test]
    fn asic_over_temp_trip_is_inclusive_at_the_vendor_limit() {
        assert_eq!(
            recommend_action(Some(108.0), Some(30.0), &A15_AC),
            ThermalAction::CutHashPower(CutReason::AsicOverTemp)
        );
        assert_eq!(
            recommend_action(Some(120.0), Some(30.0), &A15_AC),
            ThermalAction::CutHashPower(CutReason::AsicOverTemp)
        );
        assert_eq!(
            recommend_action(Some(107.9), Some(30.0), &A15_AC),
            ThermalAction::Nominal
        );
    }

    #[test]
    fn nominal_and_inlet_paths_behave_per_declared_capability() {
        // Healthy air-cooled board.
        assert_eq!(
            recommend_action(Some(75.0), Some(30.0), &A15_AC),
            ThermalAction::Nominal
        );
        // Air-cooled board with a hot room => cut (never "spin the fans up").
        assert_eq!(
            recommend_action(Some(75.0), Some(65.0), &A15_AC),
            ThermalAction::CutHashPower(CutReason::InletOutOfEnvelope)
        );
        // Air-cooled board that lost its inlet sensor => cut.
        assert_eq!(
            recommend_action(Some(75.0), None, &A15_AC),
            ThermalAction::CutHashPower(CutReason::SensorLoss)
        );
        // Hydro board has no fans, so a missing/odd inlet is not a fault.
        assert_eq!(
            recommend_action(Some(75.0), None, &A15_HYDRO),
            ThermalAction::Nominal
        );
        assert_eq!(
            recommend_action(Some(75.0), Some(65.0), &A15_HYDRO),
            ThermalAction::Nominal
        );
    }

    /// This module must remain READ-ONLY. It is the layer a future HAL will call
    /// with raw bytes; if a fan actuator or a PSU write ever lands here, the
    /// "telemetry only" contract that justified shipping it un-benched is void.
    /// Literals are split so this assertion cannot satisfy itself from its own
    /// source text.
    #[test]
    fn this_module_defines_no_actuator() {
        const SRC: &str = include_str!("thermal.rs");
        for banned in [
            concat!("fn ", "set_fan_", "duty"),
            concat!("fn ", "fan_pid_", "control"),
            concat!("fn ", "set_fan_", "fixed_duty"),
            concat!("fn ", "power_set_", "vol"),
        ] {
            assert!(
                !SRC.contains(banned),
                "read-only thermal module must not define {banned}"
            );
        }
    }
}
