// DCENT_axe — thermal sensor-adequacy assessment (host-pure)
// Copyright (C) 2026 D-Central Technologies
// License: GPL-3.0
//
//! Host-pure temperature fold + sensor-adequacy decision for the supervisor loop.
//!
//! The `main.rs` thermal supervisor used to fold every sensor
//! `[chip_temp, gt_temp2, board_temp, inlet_temp, outlet_temp, vreg_temp]`
//! into `max_temp` inline and trip a THERMAL-BLIND kill **only** when EVERY
//! sensor was `None`. That was a fail-OPEN (ES-2): the ASIC-die diode
//! (`chip_temp` / `gt_temp2`) is the hottest, safety-relevant point, while
//! `board_temp` / `inlet_temp` / `outlet_temp` / `vreg_temp` are cooler
//! **proxies** that read the PCB / airflow / regulator ~10-20 C BELOW the die.
//! If the die sensor faulted (`chip_temp = None`) while a cooler proxy stayed
//! valid, `max_temp` was taken from the proxy — so the die could reach ~120 C
//! while `max_temp` read ~100 C and the overtemp cut fired late or never.
//!
//! This module extracts the fold + adequacy decision into a pure function over
//! plain `Option<f32>` inputs (no esp-idf, no locks) so it host-compiles and
//! unit-tests under `cargo test -p dcentaxe-core` — re-included via `#[path]` in
//! `dcentaxe-core/src/lib.rs`, the same single-source-of-truth pattern used by
//! `mqtt_ha.rs` / `metrics_render.rs` / `derived_metrics.rs`. The esp-idf
//! supervisor stays thin: it gathers the live readings and calls
//! [`evaluate_thermal`], then acts on the returned assessment.

/// Outcome of assessing one temperature-sensor snapshot.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThermalAssessment {
    /// Hottest valid reading across ALL sensors (die + proxy). `0.0` when every
    /// input is `None` — identical fold to the legacy inline
    /// `.filter_map(..).fold(0.0, f32::max)`.
    pub max_temp: f32,
    /// At least one sensor returned a reading. Drives the existing all-`None`
    /// THERMAL-BLIND path and the I2C-dead watchdog — same semantics as the
    /// legacy inline `chip_temp.is_some() || .. || vreg_temp.is_some()`.
    pub any_temp_valid: bool,
    /// **ES-2 fail-closed flag.** The board IS expected to report an ASIC-die
    /// temperature, but NO die-class sensor is currently readable while at least
    /// one cooler proxy still is. In that state `max_temp` is proxy-derived and
    /// understates the true die temperature, so the supervisor must treat it as
    /// blind for the die (escalate to fail-closed), NOT trust the proxy max.
    ///
    /// Always `false` when the board is not expected to carry a die sensor
    /// (`chip_die_expected = false`) so a board that legitimately reads only a
    /// regulator/board proxy is never false-killed.
    pub die_reading_blind: bool,
}

/// Fold the six live supervisor temperatures and decide sensor adequacy.
///
/// Inputs mirror the six `Option<f32>` locals in the `main.rs` loop:
/// * `chip_temp` / `gt_temp2` — **die-class**: the ASIC-junction diode reading(s).
///   `gt_temp2` is the second ASIC-die diode on EMC2103 (GT) boards and is
///   always `None` on every other board.
/// * `board_temp` / `inlet_temp` / `outlet_temp` / `vreg_temp` — cooler
///   **proxies** (EMC internal / TMP1075 airflow / TPS546 regulator), which read
///   ~10-20 C below the die.
///
/// `chip_die_expected` must be `true` for every board that physically carries an
/// ASIC-die / junction-diode sensor (EMC2101 external diode, EMC2103 chip
/// sensor, or Hex TMP1075s — i.e. any board whose configured `temp_sensor` is not
/// `None`, or any EMC2103 board). It must be `false` only for a board whose sole
/// configured thermal source is a cooler proxy (e.g. a custom board with
/// `temp_sensor = None` relying only on the TPS546 regulator temperature): on
/// those boards a missing `chip_temp` is NORMAL and must never be treated as
/// blind.
pub fn evaluate_thermal(
    chip_temp: Option<f32>,
    gt_temp2: Option<f32>,
    board_temp: Option<f32>,
    inlet_temp: Option<f32>,
    outlet_temp: Option<f32>,
    vreg_temp: Option<f32>,
    chip_die_expected: bool,
) -> ThermalAssessment {
    let chip_temp = finite_temperature(chip_temp);
    let gt_temp2 = finite_temperature(gt_temp2);
    let board_temp = finite_temperature(board_temp);
    let inlet_temp = finite_temperature(inlet_temp);
    let outlet_temp = finite_temperature(outlet_temp);
    let vreg_temp = finite_temperature(vreg_temp);

    let all = [
        chip_temp,
        gt_temp2,
        board_temp,
        inlet_temp,
        outlet_temp,
        vreg_temp,
    ];

    // Byte-identical to the legacy inline fold: hottest valid reading, 0.0 when
    // none are valid.
    let max_temp = all.iter().filter_map(|t| *t).fold(0.0_f32, f32::max);

    // Byte-identical to the legacy inline `any_temp_valid`.
    let any_temp_valid = all.iter().any(|t| t.is_some());

    // Die-class readings vs cooler proxies.
    let have_die_reading = chip_temp.is_some() || gt_temp2.is_some();
    let have_proxy_reading = board_temp.is_some()
        || inlet_temp.is_some()
        || outlet_temp.is_some()
        || vreg_temp.is_some();

    // Fail-closed (ES-2): on a die-equipped board, losing EVERY die sensor while
    // a cooler proxy remains means `max_temp` is proxy-derived and can sit
    // 10-20 C BELOW the true die temp. Flag it so the supervisor escalates to
    // the THERMAL-BLIND fail-closed path instead of trusting the proxy max.
    //
    // Note this is mutually exclusive with the all-`None` case: when
    // `!any_temp_valid`, `have_proxy_reading` is false, so `die_reading_blind`
    // is false and the existing all-`None` BLIND path handles it.
    let die_reading_blind = chip_die_expected && !have_die_reading && have_proxy_reading;

    ThermalAssessment {
        max_temp,
        any_temp_valid,
        die_reading_blind,
    }
}

fn finite_temperature(reading: Option<f32>) -> Option<f32> {
    reading.filter(|temp| temp.is_finite())
}

/// A sweep of per-ASIC die readings from a multiplexed sensor, with the number
/// of dies actually measured **counted** rather than inferred.
///
/// A muxed board reads one die at a time: the NerdOCTAXE-γ fans two TMP451s
/// across four analog mux channels to reach eight BM1370 diodes. Any subset of
/// those reads can fail on its own (an open-circuit diode, an I2C NAK, a
/// one-shot that never clears BUSY) while the rest keep answering perfectly.
///
/// This type exists because folding such a sweep with `max` alone is a
/// **fail-open**, and upstream demonstrates the exact bug:
///
/// ```text
/// m_chipTempMax = intChipTempMax ? intChipTempMax : tmp1075Max;
/// ```
///
/// A NAN channel contributes `0.0` to their max, so one live channel at 45 C
/// with three dead ones yields a truthy `45.0`, silently discards the TMP1075
/// fallback, and reports a board whose other three dies are **unmeasured** as
/// a healthy 45 C. On a board where every die shares one rail and one fan, an
/// unmeasured die is an unprotected die: the seven you can see tell you nothing
/// about the one you cannot.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MuxedDieFold {
    /// Hottest finite per-ASIC reading in the sweep, or `None` when the whole
    /// sweep failed. Still fed to the fold so a hot die that *was* measured can
    /// trip the overtemp cut even while coverage is incomplete.
    pub hottest: Option<f32>,
    /// How many dies returned a finite reading this sweep.
    pub covered: u8,
    /// How many dies the board declares. Coverage is complete only at equality.
    pub expected: u8,
}

impl MuxedDieFold {
    /// Every declared die was measured this sweep.
    ///
    /// Deliberately `covered == expected`, not `>=`: a caller handing more
    /// readings than the board declares has a channel→ASIC map that disagrees
    /// with the board row, and that mismatch must fail closed rather than
    /// round up to "complete". `expected == 0` is never complete — a board with
    /// no declared dies should not be folding a die sweep at all.
    pub fn is_complete(&self) -> bool {
        self.expected > 0 && self.covered == self.expected
    }
}

/// Fold a per-ASIC sweep, counting how many dies actually answered.
///
/// `readings` is indexed by ASIC, in the order the caller swept them; a failed
/// read is `None`. Non-finite values are treated as failures, exactly as
/// [`evaluate_thermal`] treats them — a NAN must never count as coverage.
pub fn fold_muxed_die_readings(readings: &[Option<f32>], expected: u8) -> MuxedDieFold {
    let mut hottest: Option<f32> = None;
    let mut covered: u8 = 0;

    for reading in readings.iter().copied().filter_map(finite_temperature) {
        hottest = Some(match hottest {
            Some(current) => current.max(reading),
            None => reading,
        });
        covered = covered.saturating_add(1);
    }

    MuxedDieFold {
        hottest,
        covered,
        expected,
    }
}

/// [`evaluate_thermal`] for a board whose die readings come from a mux sweep.
///
/// Identical to the unmuxed path except that **incomplete coverage is itself
/// blindness**. Without this, a sweep that measured one die out of eight would
/// hand `evaluate_thermal` a perfectly valid `chip_temp`, satisfy
/// `have_die_reading`, and report the board as fully sighted — the fail-open
/// this whole type exists to refuse.
///
/// Note the two flags are independent and both are honoured: `max_temp` still
/// carries the hottest die that *was* measured, so the ordinary overtemp cut
/// can fire on it, while `die_reading_blind` tells the supervisor it cannot
/// trust that number to represent the board.
pub fn evaluate_thermal_muxed(
    die: MuxedDieFold,
    board_temp: Option<f32>,
    inlet_temp: Option<f32>,
    outlet_temp: Option<f32>,
    vreg_temp: Option<f32>,
    chip_die_expected: bool,
) -> ThermalAssessment {
    let mut assessment = evaluate_thermal(
        die.hottest,
        None,
        board_temp,
        inlet_temp,
        outlet_temp,
        vreg_temp,
        chip_die_expected,
    );

    assessment.die_reading_blind |= chip_die_expected && !die.is_complete();
    assessment
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHIP_EXPECTED: bool = true;
    const NO_CHIP: bool = false;

    // ── ES-2 core: die sensor faults while a cooler proxy stays valid ────────
    // The reported bug: chip_temp=None + board=70 on a chip-expected board must
    // be BLIND (fail-closed), NOT "70 is fine".
    #[test]
    fn chip_none_with_valid_proxy_on_expected_board_is_die_blind() {
        let a = evaluate_thermal(
            None,       // chip_temp — die sensor faulted
            None,       // gt_temp2
            Some(70.0), // board_temp — cooler proxy, still valid
            None,
            None,
            None,
            CHIP_EXPECTED,
        );
        assert!(
            a.die_reading_blind,
            "must flag die-blind, not trust the proxy"
        );
        assert!(a.any_temp_valid, "a proxy is still valid (not all-None)");
        // The proxy max is deliberately NOT trusted for the die: the flag tells
        // the supervisor to fail closed regardless of this value.
        assert_eq!(a.max_temp, 70.0);
    }

    #[test]
    fn chip_none_with_multiple_cooler_proxies_is_die_blind() {
        // Realistic single-ASIC TPS546 board (e.g. Gamma / Ultra 207): external
        // diode dead, EMC internal (board) + regulator (vreg) still read cool.
        let a = evaluate_thermal(
            None,       // chip_temp (external diode) faulted
            None,       // gt_temp2
            Some(85.0), // board_temp (EMC internal proxy)
            None,       // inlet
            None,       // outlet
            Some(90.0), // vreg_temp (TPS546 proxy)
            CHIP_EXPECTED,
        );
        assert!(a.die_reading_blind);
        assert!(a.any_temp_valid);
        assert_eq!(a.max_temp, 90.0);
    }

    // ── Normal: every sensor present → not blind, correct fold ───────────────
    #[test]
    fn all_sensors_present_is_normal() {
        let a = evaluate_thermal(
            Some(95.0), // chip die (hottest)
            None,
            Some(80.0),
            Some(45.0),
            Some(60.0),
            Some(72.0),
            CHIP_EXPECTED,
        );
        assert!(!a.die_reading_blind, "die reading present → never blind");
        assert!(a.any_temp_valid);
        assert_eq!(a.max_temp, 95.0, "max is the die reading");
    }

    #[test]
    fn die_hotter_than_proxy_folds_to_die() {
        // Proxy cool, die hot — the fold must surface the die.
        let a = evaluate_thermal(
            Some(110.0), // die
            None,
            Some(90.0), // proxy 20 C below
            None,
            None,
            None,
            CHIP_EXPECTED,
        );
        assert!(!a.die_reading_blind);
        assert_eq!(a.max_temp, 110.0);
    }

    // ── No false-kill: a board that legitimately has NO chip diode ───────────
    #[test]
    fn chipless_board_with_proxies_is_not_blind() {
        // e.g. a custom board with temp_sensor=None relying on TPS546 vreg temp.
        // chip_temp is None BY DESIGN here — must NOT be treated as blind.
        let a = evaluate_thermal(
            None,       // chip_temp — normal absence
            None,       // gt_temp2
            None,       // board_temp
            None,       // inlet
            None,       // outlet
            Some(65.0), // vreg_temp — the board's only (proxy) source
            NO_CHIP,
        );
        assert!(
            !a.die_reading_blind,
            "chipless board must never be false-killed"
        );
        assert!(a.any_temp_valid);
        assert_eq!(a.max_temp, 65.0);
    }

    // ── all-None → BLIND via any_temp_valid, NOT via die_reading_blind ───────
    #[test]
    fn all_none_is_all_sensors_failed_blind() {
        let a = evaluate_thermal(None, None, None, None, None, None, CHIP_EXPECTED);
        assert!(!a.any_temp_valid, "all-None → existing THERMAL-BLIND path");
        assert!(
            !a.die_reading_blind,
            "all-None is handled by any_temp_valid, not die_reading_blind (no proxy present)"
        );
        assert_eq!(a.max_temp, 0.0);
    }

    #[test]
    fn all_none_on_chipless_board_is_also_all_sensors_failed() {
        let a = evaluate_thermal(None, None, None, None, None, None, NO_CHIP);
        assert!(!a.any_temp_valid);
        assert!(!a.die_reading_blind);
        assert_eq!(a.max_temp, 0.0);
    }

    #[test]
    fn non_finite_temperatures_do_not_count_as_valid() {
        let a = evaluate_thermal(
            Some(f32::NAN),
            Some(f32::INFINITY),
            Some(f32::NEG_INFINITY),
            None,
            None,
            None,
            CHIP_EXPECTED,
        );
        assert!(
            !a.any_temp_valid,
            "NaN/Inf readings must behave like missing sensors"
        );
        assert!(!a.die_reading_blind);
        assert_eq!(a.max_temp, 0.0);
    }

    #[test]
    fn non_finite_die_with_valid_proxy_is_die_blind() {
        let a = evaluate_thermal(
            Some(f32::NAN),
            Some(f32::INFINITY),
            Some(70.0),
            None,
            None,
            None,
            CHIP_EXPECTED,
        );
        assert!(
            a.die_reading_blind,
            "invalid die readings cannot make a cooler proxy trusted"
        );
        assert!(a.any_temp_valid);
        assert_eq!(a.max_temp, 70.0);
    }

    // ── GT (EMC2103) two-die behavior ────────────────────────────────────────
    #[test]
    fn gt_primary_die_dead_but_secondary_die_valid_is_not_blind() {
        // GT has TWO ASIC-die sensors (chip_temp + gt_temp2). If only the
        // primary faults, we still have a real die reading → not blind, and the
        // secondary die temp feeds max_temp (it reads AT die temp, not a proxy).
        let a = evaluate_thermal(
            None,        // primary chip die dead
            Some(102.0), // secondary die still valid
            None,
            None,
            None,
            Some(80.0), // vreg proxy
            CHIP_EXPECTED,
        );
        assert!(!a.die_reading_blind, "a valid die reading remains");
        assert_eq!(a.max_temp, 102.0);
    }

    #[test]
    fn gt_both_dies_dead_with_vreg_proxy_is_die_blind() {
        // Both EMC2103 die sensors dead, only the TPS546 regulator proxy left.
        let a = evaluate_thermal(
            None, // primary die dead
            None, // secondary die dead
            None,
            None,
            None,
            Some(88.0), // vreg proxy
            CHIP_EXPECTED,
        );
        assert!(a.die_reading_blind);
        assert!(a.any_temp_valid);
        assert_eq!(a.max_temp, 88.0);
    }

    // ── Die present but proxy hotter (rare) still not blind ──────────────────
    #[test]
    fn die_present_with_hotter_proxy_is_not_blind_and_folds_to_proxy() {
        let a = evaluate_thermal(
            Some(70.0), // die reading present
            None,
            None,
            None,
            None,
            Some(75.0), // proxy happens to read higher
            CHIP_EXPECTED,
        );
        assert!(!a.die_reading_blind, "we have a die reading → not blind");
        assert_eq!(a.max_temp, 75.0, "fold still surfaces the hottest reading");
    }

    // ── Muxed per-ASIC sweeps: coverage is COUNTED, never inferred ───────────
    // A muxed board reads one die at a time, so a sweep can half-succeed. The
    // whole point of these tests is that a half-successful sweep is BLIND.

    const OCTAXE_ASICS: u8 = 8; // NerdOCTAXE-γ: 2 TMP451s x 4 mux channels

    fn all_measured(temp: f32, n: usize) -> Vec<Option<f32>> {
        vec![Some(temp); n]
    }

    #[test]
    fn fold_counts_coverage_and_picks_the_hottest_die() {
        let f = fold_muxed_die_readings(
            &[Some(70.0), Some(91.5), None, Some(68.0)],
            4, // expected
        );
        assert_eq!(f.hottest, Some(91.5), "hottest measured die");
        assert_eq!(f.covered, 3, "three dies answered");
        assert_eq!(f.expected, 4);
        assert!(!f.is_complete(), "3 of 4 is not coverage");
    }

    #[test]
    fn fold_does_not_count_non_finite_readings_as_coverage() {
        // A NAN is the exact value upstream folds into its max as 0.0.
        let f = fold_muxed_die_readings(
            &[Some(45.0), Some(f32::NAN), Some(f32::NAN), Some(f32::NAN)],
            4,
        );
        assert_eq!(f.covered, 1, "NAN is a failed read, not a measured die");
        assert_eq!(f.hottest, Some(45.0));
        assert!(!f.is_complete());
    }

    #[test]
    fn complete_sweep_is_not_blind_and_surfaces_the_hottest_die() {
        let mut readings = all_measured(72.0, OCTAXE_ASICS as usize);
        readings[5] = Some(96.0); // one die running hot
        let f = fold_muxed_die_readings(&readings, OCTAXE_ASICS);
        assert!(f.is_complete(), "8 of 8 measured");

        let a = evaluate_thermal_muxed(f, Some(60.0), None, None, Some(70.0), CHIP_EXPECTED);
        assert!(!a.die_reading_blind, "full coverage → sighted");
        assert!(a.any_temp_valid);
        assert_eq!(a.max_temp, 96.0, "the hot die drives the fold");
    }

    #[test]
    fn partial_sweep_of_cool_dies_is_blind_even_though_every_reading_looks_fine() {
        // THE upstream defect, in our own shape: 7 of 8 dies read a comfortable
        // 65 C. Nothing about those seven readings is suspicious. The eighth is
        // unmeasured, shares the rail and the fan, and could be anywhere.
        let mut readings = all_measured(65.0, OCTAXE_ASICS as usize);
        readings[3] = None;
        let f = fold_muxed_die_readings(&readings, OCTAXE_ASICS);

        let a = evaluate_thermal_muxed(f, Some(55.0), None, None, None, CHIP_EXPECTED);
        assert!(
            a.die_reading_blind,
            "7 of 8 dies is not coverage — an unmeasured die is an unprotected die"
        );
        assert_eq!(f.covered, 7);
        assert!(!f.is_complete());
    }

    #[test]
    fn partial_sweep_still_folds_the_measured_dies_into_max_temp() {
        // Blindness must not suppress a real overtemp: the die we DID measure is
        // at 108 C, and the cut has to be able to fire on it.
        let mut readings = vec![None; OCTAXE_ASICS as usize];
        readings[0] = Some(108.0);
        let f = fold_muxed_die_readings(&readings, OCTAXE_ASICS);

        let a = evaluate_thermal_muxed(f, Some(60.0), None, None, None, CHIP_EXPECTED);
        assert!(a.die_reading_blind, "1 of 8 is blind");
        assert_eq!(
            a.max_temp, 108.0,
            "the measured die must still reach the overtemp cut"
        );
        assert!(a.any_temp_valid);
    }

    #[test]
    fn partial_sweep_does_not_discard_the_proxy_the_way_upstream_does() {
        // Upstream's `intChipTempMax ? intChipTempMax : tmp1075Max` throws the
        // TMP1075 away the moment ONE channel is truthy. Ours folds both.
        let f = fold_muxed_die_readings(&[Some(45.0), None, None, None], 4);
        let a = evaluate_thermal_muxed(
            f,
            None,
            None,
            None,
            Some(88.0), // proxy is hotter than the one die we reached
            CHIP_EXPECTED,
        );
        assert_eq!(a.max_temp, 88.0, "the proxy is still in the fold");
        assert!(a.die_reading_blind);
    }

    #[test]
    fn totally_failed_sweep_with_a_proxy_is_blind() {
        let f = fold_muxed_die_readings(&[None; 8], OCTAXE_ASICS);
        assert_eq!(f.hottest, None);
        assert_eq!(f.covered, 0);

        let a = evaluate_thermal_muxed(f, Some(70.0), None, None, None, CHIP_EXPECTED);
        assert!(a.die_reading_blind, "no die reading at all → blind");
        assert!(a.any_temp_valid, "the proxy still reads");
    }

    #[test]
    fn totally_failed_sweep_with_no_proxy_is_the_all_sensors_failed_path() {
        let f = fold_muxed_die_readings(&[None; 8], OCTAXE_ASICS);
        let a = evaluate_thermal_muxed(f, None, None, None, None, CHIP_EXPECTED);
        assert!(!a.any_temp_valid, "all-None → existing THERMAL-BLIND path");
        assert_eq!(a.max_temp, 0.0);
    }

    #[test]
    fn more_readings_than_the_board_declares_fails_closed() {
        // A channel→ASIC map that disagrees with the board row. Rounding this up
        // to "complete" would trust a map we know is wrong.
        let f = fold_muxed_die_readings(&all_measured(60.0, 9), OCTAXE_ASICS);
        assert_eq!(f.covered, 9);
        assert!(
            !f.is_complete(),
            "covered > expected is a map mismatch, not extra credit"
        );

        let a = evaluate_thermal_muxed(f, None, None, None, Some(50.0), CHIP_EXPECTED);
        assert!(a.die_reading_blind);
    }

    #[test]
    fn a_board_declaring_no_dies_is_never_complete() {
        let f = fold_muxed_die_readings(&[Some(60.0)], 0);
        assert!(
            !f.is_complete(),
            "expected == 0 means this board should not be sweeping dies at all"
        );
    }

    #[test]
    fn incomplete_coverage_on_a_chipless_board_is_not_a_false_kill() {
        // Same no-false-kill guarantee as the unmuxed path: a board that is not
        // expected to carry die sensors must never be blinded by their absence.
        let f = fold_muxed_die_readings(&[None; 4], 4);
        let a = evaluate_thermal_muxed(f, None, None, None, Some(65.0), NO_CHIP);
        assert!(!a.die_reading_blind, "chipless board must never be blinded");
        assert_eq!(a.max_temp, 65.0);
    }

    #[test]
    fn muxed_path_agrees_with_the_unmuxed_path_when_coverage_is_complete() {
        // The muxed wrapper must add blindness and nothing else — same fold,
        // same any_temp_valid, for an identical set of inputs.
        let f = fold_muxed_die_readings(&all_measured(80.0, 4), 4);
        let muxed =
            evaluate_thermal_muxed(f, Some(60.0), Some(30.0), Some(50.0), None, CHIP_EXPECTED);
        let unmuxed = evaluate_thermal(
            Some(80.0),
            None,
            Some(60.0),
            Some(30.0),
            Some(50.0),
            None,
            CHIP_EXPECTED,
        );
        assert_eq!(muxed, unmuxed);
    }
}
