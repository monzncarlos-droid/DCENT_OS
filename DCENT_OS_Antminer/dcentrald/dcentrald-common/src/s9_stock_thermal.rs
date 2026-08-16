//! Release-scoped S9j stock thermal/fan contract (pure, no I/O).
//!
//! This module records the hardware-facing behavior recovered from the exact
//! 2019-06-30 S9j recovery `bmminer` whose SHA-256 starts with `e5312ad1`.
//! It is deliberately **not** a generic `am1-s9` policy: the standard
//! Braiins/DCENT FPGA image exposes a different fan controller, and the held
//! evidence does not prove that every S9/S9i/S9j release uses this policy.
//!
//! The planner consumes already-acquired samples. It neither reads FPGA/I2C
//! registers nor authorizes a live fan, PIC, DHASH, or work-dispatch write.
//! A caller must still pass the top-level stock-FPGA admission gate and apply
//! the repository's independent home fan/noise policy.

use crate::stock_fpga_policy::{
    stock_fan_control_value, stock_sensor_get_local, stock_sensor_get_remote_c,
};
use crate::work_dispatch_safety::ThermalSafetyState;

/// Full digest of the exact S9j recovery `bmminer` used for this contract.
pub const S9J_E531_BMMINER_SHA256: &str =
    "e5312ad1e5b2c086906ef96223f9b7b728ad30251264c2bb4575667651669cf2";

/// Exact evidence/release scope. Do not add a generic S9 variant without a
/// release-matched binary or bench trace that proves equivalence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9StockThermalProfile {
    /// S9j recovery image, `bmminer` built 2019-06-30, digest e531...cf2.
    S9jRecovery20190630E531,
}

/// `check_fan` reads the eight-entry tach FIFO twice.
pub const S9J_E531_FAN_SWEEPS_PER_CYCLE: u8 = 2;
/// Number of fan identifiers encoded in FAN_SPEED bits 10:8.
pub const S9J_E531_FAN_SLOT_COUNT: usize = 8;
/// One FPGA tach unit is 120 RPM (`raw * 60 * 2`).
pub const S9J_E531_FAN_TACH_RPM_PER_UNIT: u32 = 120;
/// Stock requires two non-zero tach identities while mining.
pub const S9J_E531_MIN_WORKING_FANS: u8 = 2;
/// Exact `set_PWM` lower clamp for this binary.
pub const S9J_E531_MIN_PWM_PERCENT: u8 = 20;
/// Exact `set_PWM` upper clamp.
pub const S9J_E531_MAX_PWM_PERCENT: u8 = 100;
/// Local/PCB temperature at or above this value triggers the hard-protect
/// thread (`cmp > 89`).
pub const S9J_E531_HARD_PCB_CUTOFF_C: i16 = 90;
/// Highest normal-curve temperature; 75 C and above requests full fan.
pub const S9J_E531_FULL_FAN_PCB_C: i16 = 75;
/// At or below 43 C, the binary requests its 20% floor.
pub const S9J_E531_FAN_FLOOR_MAX_PCB_C: i16 = 43;
/// Linear fan-curve origin: `20 + 2 * (pcb_c - 35)`.
pub const S9J_E531_FAN_CURVE_ORIGIN_C: i16 = 35;
/// Linear fan-curve gain in percentage points per degree C.
pub const S9J_E531_FAN_CURVE_PCT_PER_C: i16 = 2;
/// Recompute the normal curve only after an absolute 2 C change.
pub const S9J_E531_FAN_CURVE_HYSTERESIS_C: i16 = 2;
/// `check_reg_temp` makes at most two bounded transactions.
pub const S9J_E531_TEMP_READ_ATTEMPTS: u8 = 2;
/// A response is returned only when the first transaction succeeds. The exact
/// helper returns its zero failure sentinel after reaching attempt two, even
/// when that second response matched.
pub const S9J_E531_TEMP_LAST_ACCEPTED_ATTEMPT: u8 = 1;
/// Sleep appended to each main temperature/fan supervisory iteration. Sensor
/// acquisition and processing time make the start-to-start cadence longer.
pub const S9J_E531_SUPERVISORY_LOOP_SLEEP_SECS: u64 = 10;
/// Sleep appended to each independent hard-protect iteration.
pub const S9J_E531_HARD_PROTECT_LOOP_SLEEP_SECS: u64 = 3;
/// Exact S9j release requires a second consecutive supervisory fault before
/// its main loop latches a fatal fan/overtemperature stop.
pub const S9J_E531_SUPERVISORY_FAULT_CYCLES_TO_CUT: u8 = 2;
/// Lowest value representable by a successful non-zero raw local read.
pub const S9J_E531_LOCAL_DECODE_MIN_C: i16 = -63;
/// Highest value representable by the eight-bit raw local register.
pub const S9J_E531_LOCAL_DECODE_MAX_C: i16 = 191;

/// One successful FAN_SPEED FIFO read. Missing/`-1` reads are omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9StockFanTachRead {
    /// FAN_SPEED bits 10:8.
    pub fan_id: u8,
    /// FAN_SPEED bits 7:0.
    pub tach_raw: u8,
}

/// Pure result of replaying one call to `check_fan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9StockFanTachSummary {
    /// Last valid tach sample per fan identity.
    pub last_raw_by_id: [Option<u8>; S9J_E531_FAN_SLOT_COUNT],
    /// Number of identities whose last valid tach is non-zero.
    pub working_fans: u8,
    /// Slowest non-zero sample observed during this call. Stock clears this
    /// cycle accumulator without clearing per-identity presence state.
    pub min_rpm: Option<u32>,
    /// Fastest non-zero sample observed during this call.
    pub max_rpm: Option<u32>,
    /// Reads with an out-of-range fan identity, retained as evidence rather
    /// than indexing outside the fixed hardware domain.
    pub invalid_id_reads: u8,
}

/// State retained by `check_fan` across calls. Stock clears its per-cycle
/// minimum/maximum accumulators at entry, but it does not clear the identity
/// presence array or working-fan count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct S9StockFanTachState {
    last_raw_by_id: [Option<u8>; S9J_E531_FAN_SLOT_COUNT],
}

impl S9StockFanTachState {
    /// Seed replay from a previously observed identity state. This is needed
    /// for mid-run captures because a skipped `0xffff_ffff` FIFO read leaves
    /// that identity's stock presence state unchanged.
    pub const fn new(last_raw_by_id: [Option<u8>; S9J_E531_FAN_SLOT_COUNT]) -> Self {
        Self { last_raw_by_id }
    }

    /// Replay successful FIFO reads in acquisition order. The last valid
    /// sample for an identity owns its retained present/absent state, while
    /// RPM extrema cover every non-zero sample in this call.
    pub fn apply_reads(&mut self, reads: &[S9StockFanTachRead]) -> S9StockFanTachSummary {
        let mut invalid_id_reads = 0_u8;
        let mut min_rpm = None;
        let mut max_rpm = None;
        for read in reads {
            if let Some(slot) = self.last_raw_by_id.get_mut(usize::from(read.fan_id)) {
                *slot = Some(read.tach_raw);
                if read.tach_raw != 0 {
                    let rpm = u32::from(read.tach_raw) * S9J_E531_FAN_TACH_RPM_PER_UNIT;
                    min_rpm = Some(min_rpm.map_or(rpm, |old: u32| old.min(rpm)));
                    max_rpm = Some(max_rpm.map_or(rpm, |old: u32| old.max(rpm)));
                }
            } else {
                invalid_id_reads = invalid_id_reads.saturating_add(1);
            }
        }

        let working_fans = self
            .last_raw_by_id
            .into_iter()
            .flatten()
            .filter(|raw| *raw != 0)
            .count() as u8;

        S9StockFanTachSummary {
            last_raw_by_id: self.last_raw_by_id,
            working_fans,
            min_rpm,
            max_rpm,
            invalid_id_reads,
        }
    }
}

/// Replay a capture that begins with no retained fan identities. Use
/// [`S9StockFanTachState`] directly for consecutive or mid-run calls.
pub fn summarize_s9j_e531_fan_reads(reads: &[S9StockFanTachRead]) -> S9StockFanTachSummary {
    S9StockFanTachState::default().apply_reads(reads)
}

/// Decode a successful local/PCB sensor register read. Stock uses zero as its
/// failed-read sentinel; all other raw values are decoded as `raw - 64`.
pub fn decode_s9j_e531_local_pcb_c(raw: u8) -> Option<i16> {
    (raw != 0).then(|| stock_sensor_get_local(i16::from(raw)))
}

/// Decode a successful remote/junction register-1 read using the exact
/// calibrated affine transform shared by the stock sensor helper. Raw byte
/// zero is valid here: register address bits make the full response non-zero,
/// unlike a failed register-0 local read.
pub fn decode_s9j_e531_remote_c(raw: u8) -> Option<i16> {
    Some(stock_sensor_get_remote_c(i16::from(raw)))
}

/// Exact S9j `set_PWM` register pack, including this release's 20% floor.
pub fn s9j_e531_fan_control_value(requested_percent: u8) -> u32 {
    stock_fan_control_value(
        requested_percent.clamp(S9J_E531_MIN_PWM_PERCENT, S9J_E531_MAX_PWM_PERCENT),
    )
}

/// State retained by the release's fan hysteresis and fault debouncer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9StockThermalPlanner {
    profile: S9StockThermalProfile,
    last_curve_pcb_c: i16,
    vendor_pwm_percent: u8,
    consecutive_supervisory_faults: u8,
    hard_cut_latched: bool,
    hard_cut_reason: Option<S9StockCutReason>,
}

impl S9StockThermalPlanner {
    /// Construct a planner from the last observed stock fan state. Requiring
    /// explicit initial values avoids inventing the runtime's initialization
    /// point when replaying a mid-run capture.
    pub fn new(
        profile: S9StockThermalProfile,
        last_curve_pcb_c: i16,
        vendor_pwm_percent: u8,
    ) -> Self {
        Self {
            profile,
            last_curve_pcb_c,
            vendor_pwm_percent: vendor_pwm_percent
                .clamp(S9J_E531_MIN_PWM_PERCENT, S9J_E531_MAX_PWM_PERCENT),
            consecutive_supervisory_faults: 0,
            hard_cut_latched: false,
            hard_cut_reason: None,
        }
    }

    /// Evaluate one already-acquired supervisory observation.
    ///
    /// `supervisory_local_pcb_c_by_sensor_group` contains the maximum **fresh**
    /// local/PCB reading for each configured sensor-owning group. A failed read
    /// must be `None`; passing a cached or copied vendor value as fresh would
    /// erase the evidence boundary.
    pub fn plan(&mut self, observation: &S9StockThermalObservation<'_>) -> S9StockThermalPlan {
        let all_sensor_groups_fresh = !observation
            .supervisory_local_pcb_c_by_sensor_group
            .is_empty()
            && observation
                .supervisory_local_pcb_c_by_sensor_group
                .iter()
                .all(|sample| {
                    sample.is_some_and(|temp| {
                        (S9J_E531_LOCAL_DECODE_MIN_C..=S9J_E531_LOCAL_DECODE_MAX_C).contains(&temp)
                    })
                });
        let max_local_pcb_c = observation
            .supervisory_local_pcb_c_by_sensor_group
            .iter()
            .flatten()
            .copied()
            .max();
        let sensor_cycle_fresh =
            all_sensor_groups_fresh && !observation.any_local_sensor_read_failed;

        let vendor_pwm_percent = if !sensor_cycle_fresh {
            S9J_E531_MAX_PWM_PERCENT
        } else {
            self.next_vendor_pwm(max_local_pcb_c, observation.preheating)
        };
        self.vendor_pwm_percent = vendor_pwm_percent;

        let hard_overtemperature = observation
            .hard_protect_max_local_pcb_c
            .is_some_and(|temp| temp >= S9J_E531_HARD_PCB_CUTOFF_C);
        let mut cut_steps = None;
        if hard_overtemperature {
            self.latch_cut(S9StockCutReason::HardLocalPcbOvertemperature);
            cut_steps = Some(S9J_E531_HARD_PROTECT_CUT_STEPS);
        }

        let supervisory_fault = observation.fans.working_fans < S9J_E531_MIN_WORKING_FANS
            || max_local_pcb_c.is_some_and(|temp| temp > S9J_E531_HARD_PCB_CUTOFF_C);
        if supervisory_fault {
            self.consecutive_supervisory_faults =
                self.consecutive_supervisory_faults.saturating_add(1);
            if self.consecutive_supervisory_faults >= S9J_E531_SUPERVISORY_FAULT_CYCLES_TO_CUT {
                // Exact `read_temp_func` assigns overtemperature before it
                // checks the fan count when both faults are present.
                let reason =
                    if max_local_pcb_c.is_some_and(|temp| temp > S9J_E531_HARD_PCB_CUTOFF_C) {
                        S9StockCutReason::RepeatedSupervisoryOvertemperature
                    } else {
                        S9StockCutReason::RepeatedFanLoss
                    };
                self.latch_cut(reason);
                if cut_steps.is_none() {
                    cut_steps = Some(S9J_E531_SUPERVISORY_CUT_STEPS);
                }
            }
        } else {
            self.consecutive_supervisory_faults = 0;
        }

        let thermal_state = if self.hard_cut_latched {
            ThermalSafetyState::Emergency
        } else if sensor_cycle_fresh
            && observation.fans.working_fans >= S9J_E531_MIN_WORKING_FANS
            && observation.fans.invalid_id_reads == 0
        {
            ThermalSafetyState::Ready
        } else {
            // Stricter than the vendor's stale-cache continuation: cached or
            // missing readings are never positive dispatch evidence.
            ThermalSafetyState::NotReady
        };

        S9StockThermalPlan {
            profile: self.profile,
            thermal_state,
            max_local_pcb_c,
            hard_protect_max_local_pcb_c: observation.hard_protect_max_local_pcb_c,
            sensor_cycle_fresh,
            vendor_observed_pwm_percent: vendor_pwm_percent,
            vendor_observed_fan_control: s9j_e531_fan_control_value(vendor_pwm_percent),
            consecutive_supervisory_faults: self.consecutive_supervisory_faults,
            hard_cut_reason: self.hard_cut_reason,
            cut_steps,
        }
    }

    fn next_vendor_pwm(&mut self, max_local_pcb_c: Option<i16>, preheating: bool) -> u8 {
        let Some(temp) = max_local_pcb_c else {
            return S9J_E531_MAX_PWM_PERCENT;
        };

        if preheating {
            return if temp >= S9J_E531_FULL_FAN_PCB_C {
                S9J_E531_MAX_PWM_PERCENT
            } else {
                S9J_E531_MIN_PWM_PERCENT
            };
        }

        if temp == 0 || temp >= S9J_E531_FULL_FAN_PCB_C {
            return S9J_E531_MAX_PWM_PERCENT;
        }
        if temp <= S9J_E531_FAN_FLOOR_MAX_PCB_C {
            self.last_curve_pcb_c = temp;
            return S9J_E531_MIN_PWM_PERCENT;
        }
        // Widen untrusted observations before subtraction: a malformed capture
        // may legally carry either i16 extreme, and this pure replay surface
        // must not panic in debug or wrap in release.
        let temp_i32 = i32::from(temp);
        let last_i32 = i32::from(self.last_curve_pcb_c);
        if (temp_i32 - last_i32).abs() < i32::from(S9J_E531_FAN_CURVE_HYSTERESIS_C) {
            return self.vendor_pwm_percent;
        }

        self.last_curve_pcb_c = temp;
        let requested = i32::from(S9J_E531_MIN_PWM_PERCENT)
            + i32::from(S9J_E531_FAN_CURVE_PCT_PER_C)
                * (temp_i32 - i32::from(S9J_E531_FAN_CURVE_ORIGIN_C));
        requested.clamp(
            i32::from(S9J_E531_MIN_PWM_PERCENT),
            i32::from(S9J_E531_MAX_PWM_PERCENT),
        ) as u8
    }

    fn latch_cut(&mut self, reason: S9StockCutReason) {
        if !self.hard_cut_latched {
            self.hard_cut_reason = Some(reason);
        }
        self.hard_cut_latched = true;
    }
}

/// One pure observation. Acquisition and freshness ownership stay outside this
/// module so cached values cannot silently become fresh evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9StockThermalObservation<'a> {
    /// Independently acquired maximum from the sensor-owning chains selected
    /// by `check_temp_func`. `None` means no fresh hard-protect observation was
    /// made; the ten-second supervisor sample must not be substituted here.
    pub hard_protect_max_local_pcb_c: Option<i16>,
    pub supervisory_local_pcb_c_by_sensor_group: &'a [Option<i16>],
    /// Exact supervisor full-fan trigger. Remote-cache failure alone does not
    /// set this release's corresponding cycle flag.
    pub any_local_sensor_read_failed: bool,
    pub fans: S9StockFanTachSummary,
    pub preheating: bool,
}

/// Why the exact stock cut sequence was latched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9StockCutReason {
    HardLocalPcbOvertemperature,
    RepeatedSupervisoryOvertemperature,
    RepeatedFanLoss,
}

/// Hardware mutations observed in a release-specific cut path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9StockHardCutStep {
    /// For every present chain, issue `disable_pic_dac` under the I2C mutex.
    DisablePicDacForEachPresentChain,
    /// Read DHASH_ACC_CONTROL, clear RUN bit 6, then write it back.
    ClearDhashRunBit,
}

/// `check_temp_func@0x34518` immediate hard-protect sequence.
pub const S9J_E531_HARD_PROTECT_CUT_STEPS: &[S9StockHardCutStep] = &[
    S9StockHardCutStep::DisablePicDacForEachPresentChain,
    S9StockHardCutStep::ClearDhashRunBit,
];

/// `read_temp_func@0x3d898` debounced supervisor sequence. This function sets
/// fatal flags and disables PIC DACs, but contains no DHASH getter/setter call.
pub const S9J_E531_SUPERVISORY_CUT_STEPS: &[S9StockHardCutStep] =
    &[S9StockHardCutStep::DisablePicDacForEachPresentChain];

/// Pure replay classification only. Even [`ThermalSafetyState::Ready`] is not
/// a live admission receipt. `vendor_observed_*` describes e531 behavior; it
/// is not a D-Central fan-write authorization and has not been intersected
/// with the independent home acoustic cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9StockThermalPlan {
    pub profile: S9StockThermalProfile,
    pub thermal_state: ThermalSafetyState,
    pub max_local_pcb_c: Option<i16>,
    pub hard_protect_max_local_pcb_c: Option<i16>,
    pub sensor_cycle_fresh: bool,
    pub vendor_observed_pwm_percent: u8,
    pub vendor_observed_fan_control: u32,
    pub consecutive_supervisory_faults: u8,
    pub hard_cut_reason: Option<S9StockCutReason>,
    /// Mutations issued for this observation only. A latched emergency does
    /// not by itself imply that stock reissued the cut on a later cool cycle.
    pub cut_steps: Option<&'static [S9StockHardCutStep]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fans(raw: &[(u8, u8)]) -> S9StockFanTachSummary {
        let reads: Vec<_> = raw
            .iter()
            .map(|(fan_id, tach_raw)| S9StockFanTachRead {
                fan_id: *fan_id,
                tach_raw: *tach_raw,
            })
            .collect();
        summarize_s9j_e531_fan_reads(&reads)
    }

    fn observation<'a>(
        temps: &'a [Option<i16>],
        fans: S9StockFanTachSummary,
    ) -> S9StockThermalObservation<'a> {
        S9StockThermalObservation {
            hard_protect_max_local_pcb_c: None,
            supervisory_local_pcb_c_by_sensor_group: temps,
            any_local_sensor_read_failed: false,
            fans,
            preheating: false,
        }
    }

    #[test]
    fn tach_replay_uses_last_sample_and_exact_rpm_scale() {
        let summary = fans(&[(3, 45), (6, 44), (3, 0), (6, 46), (8, 99)]);
        assert_eq!(summary.working_fans, 1);
        assert_eq!(summary.last_raw_by_id[3], Some(0));
        assert_eq!(summary.last_raw_by_id[6], Some(46));
        assert_eq!(summary.min_rpm, Some(5_280));
        assert_eq!(summary.max_rpm, Some(5_520));
        assert_eq!(summary.invalid_id_reads, 1);
    }

    #[test]
    fn tach_replay_retains_absent_from_capture_identity_but_resets_cycle_extrema() {
        let mut state = S9StockFanTachState::default();
        let first = state.apply_reads(&[
            S9StockFanTachRead {
                fan_id: 3,
                tach_raw: 50,
            },
            S9StockFanTachRead {
                fan_id: 6,
                tach_raw: 40,
            },
        ]);
        assert_eq!(first.working_fans, 2);
        assert_eq!(first.max_rpm, Some(6_000));

        let second = state.apply_reads(&[S9StockFanTachRead {
            fan_id: 6,
            tach_raw: 41,
        }]);
        assert_eq!(
            second.working_fans, 2,
            "omitted identity retains stock state"
        );
        assert_eq!(second.last_raw_by_id[3], Some(50));
        assert_eq!(second.min_rpm, Some(4_920));
        assert_eq!(second.max_rpm, Some(4_920));
    }

    #[test]
    fn local_and_remote_decoders_preserve_failed_read_sentinel() {
        assert_eq!(decode_s9j_e531_local_pcb_c(0), None);
        assert_eq!(decode_s9j_e531_local_pcb_c(64), Some(0));
        assert_eq!(decode_s9j_e531_local_pcb_c(132), Some(68));
        assert_eq!(decode_s9j_e531_remote_c(0), Some(-83));
        assert_eq!(decode_s9j_e531_remote_c(100), Some(7));
    }

    #[test]
    fn exact_pwm_floor_and_live_golden_are_pinned() {
        assert_eq!(s9j_e531_fan_control_value(0), 0x000A_0028);
        assert_eq!(s9j_e531_fan_control_value(20), 0x000A_0028);
        assert_eq!(s9j_e531_fan_control_value(88), 0x002C_0006);
        assert_eq!(s9j_e531_fan_control_value(100), 0x0032_0000);
    }

    #[test]
    fn exact_curve_boundaries_and_hysteresis_are_pinned() {
        let good_fans = fans(&[(3, 45), (6, 45)]);
        let mut planner =
            S9StockThermalPlanner::new(S9StockThermalProfile::S9jRecovery20190630E531, 40, 20);

        let at_43 = planner.plan(&observation(&[Some(43); 3], good_fans));
        assert_eq!(at_43.vendor_observed_pwm_percent, 20);
        let at_44 = planner.plan(&observation(&[Some(44); 3], good_fans));
        assert_eq!(at_44.vendor_observed_pwm_percent, 20, "1 C change holds");
        let at_45 = planner.plan(&observation(&[Some(45); 3], good_fans));
        assert_eq!(at_45.vendor_observed_pwm_percent, 40);
        let at_46 = planner.plan(&observation(&[Some(46); 3], good_fans));
        assert_eq!(at_46.vendor_observed_pwm_percent, 40, "1 C change holds");
        let at_74 = planner.plan(&observation(&[Some(74); 3], good_fans));
        assert_eq!(at_74.vendor_observed_pwm_percent, 98);
        let at_75 = planner.plan(&observation(&[Some(75); 3], good_fans));
        assert_eq!(at_75.vendor_observed_pwm_percent, 100);
    }

    #[test]
    fn zero_and_preheat_use_exact_full_or_floor_policy() {
        let good_fans = fans(&[(3, 45), (6, 45)]);
        let mut planner =
            S9StockThermalPlanner::new(S9StockThermalProfile::S9jRecovery20190630E531, 40, 50);
        assert_eq!(
            planner
                .plan(&observation(&[Some(0); 3], good_fans))
                .vendor_observed_pwm_percent,
            100
        );
        let mut preheat = observation(&[Some(74); 3], good_fans);
        preheat.preheating = true;
        assert_eq!(planner.plan(&preheat).vendor_observed_pwm_percent, 20);
        let mut preheat_hot = observation(&[Some(75); 3], good_fans);
        preheat_hot.preheating = true;
        assert_eq!(planner.plan(&preheat_hot).vendor_observed_pwm_percent, 100);
    }

    #[test]
    fn readiness_requires_fresh_local_sample_for_every_sensor_group_and_two_fans() {
        let good_fans = fans(&[(3, 45), (6, 45)]);
        let mut planner =
            S9StockThermalPlanner::new(S9StockThermalProfile::S9jRecovery20190630E531, 60, 70);
        assert_eq!(
            planner
                .plan(&observation(&[Some(60), Some(61), Some(62)], good_fans))
                .thermal_state,
            ThermalSafetyState::Ready
        );
        let missing = planner.plan(&observation(&[Some(60), None, Some(62)], good_fans));
        assert_eq!(missing.thermal_state, ThermalSafetyState::NotReady);
        assert!(!missing.sensor_cycle_fresh);
        assert_eq!(missing.vendor_observed_pwm_percent, 100);
    }

    #[test]
    fn fan_loss_is_not_ready_immediately_and_exact_cut_latches_on_second_cycle() {
        let one_fan = fans(&[(3, 45), (6, 0)]);
        let mut planner =
            S9StockThermalPlanner::new(S9StockThermalProfile::S9jRecovery20190630E531, 60, 70);
        let first = planner.plan(&observation(&[Some(60); 3], one_fan));
        assert_eq!(first.thermal_state, ThermalSafetyState::NotReady);
        assert_eq!(first.consecutive_supervisory_faults, 1);
        assert_eq!(first.cut_steps, None);

        let second = planner.plan(&observation(&[Some(60); 3], one_fan));
        assert_eq!(second.thermal_state, ThermalSafetyState::Emergency);
        assert_eq!(
            second.hard_cut_reason,
            Some(S9StockCutReason::RepeatedFanLoss)
        );
        assert_eq!(second.cut_steps, Some(S9J_E531_SUPERVISORY_CUT_STEPS));
    }

    #[test]
    fn supervisor_overtemperature_is_strictly_above_90_and_pic_only() {
        let good_fans = fans(&[(3, 45), (6, 45)]);
        let mut planner =
            S9StockThermalPlanner::new(S9StockThermalProfile::S9jRecovery20190630E531, 89, 100);

        let at_90 = planner.plan(&observation(&[Some(90); 3], good_fans));
        assert_eq!(at_90.consecutive_supervisory_faults, 0);
        assert_eq!(at_90.cut_steps, None);

        let first_91 = planner.plan(&observation(&[Some(91); 3], good_fans));
        assert_eq!(first_91.consecutive_supervisory_faults, 1);
        assert_eq!(first_91.cut_steps, None);

        let second_91 = planner.plan(&observation(&[Some(91); 3], good_fans));
        assert_eq!(
            second_91.hard_cut_reason,
            Some(S9StockCutReason::RepeatedSupervisoryOvertemperature)
        );
        assert_eq!(second_91.cut_steps, Some(S9J_E531_SUPERVISORY_CUT_STEPS));
        assert!(!S9J_E531_SUPERVISORY_CUT_STEPS.contains(&S9StockHardCutStep::ClearDhashRunBit));
    }

    #[test]
    fn simultaneous_supervisor_faults_report_overtemperature_before_fan_loss() {
        let one_fan = fans(&[(3, 45)]);
        let mut planner =
            S9StockThermalPlanner::new(S9StockThermalProfile::S9jRecovery20190630E531, 89, 100);
        let both = observation(&[Some(91); 3], one_fan);
        assert_eq!(planner.plan(&both).consecutive_supervisory_faults, 1);
        let second = planner.plan(&both);
        assert_eq!(
            second.hard_cut_reason,
            Some(S9StockCutReason::RepeatedSupervisoryOvertemperature)
        );
    }

    #[test]
    fn hard_cut_is_immediate_at_90_and_order_is_pic_then_dhash() {
        let good_fans = fans(&[(3, 45), (6, 45)]);
        let mut planner =
            S9StockThermalPlanner::new(S9StockThermalProfile::S9jRecovery20190630E531, 88, 100);
        let mut observation = observation(&[Some(89), Some(90), Some(88)], good_fans);
        observation.hard_protect_max_local_pcb_c = Some(90);
        let plan = planner.plan(&observation);
        assert_eq!(plan.thermal_state, ThermalSafetyState::Emergency);
        assert_eq!(
            plan.hard_cut_reason,
            Some(S9StockCutReason::HardLocalPcbOvertemperature)
        );
        assert_eq!(
            plan.cut_steps,
            Some(
                &[
                    S9StockHardCutStep::DisablePicDacForEachPresentChain,
                    S9StockHardCutStep::ClearDhashRunBit,
                ][..]
            )
        );
    }

    #[test]
    fn healthy_cycle_resets_unlatched_supervisory_debounce() {
        let one_fan = fans(&[(3, 45)]);
        let two_fans = fans(&[(3, 45), (6, 45)]);
        let mut planner =
            S9StockThermalPlanner::new(S9StockThermalProfile::S9jRecovery20190630E531, 60, 70);
        assert_eq!(
            planner
                .plan(&observation(&[Some(60); 3], one_fan))
                .consecutive_supervisory_faults,
            1
        );
        assert_eq!(
            planner
                .plan(&observation(&[Some(60); 3], two_fans))
                .consecutive_supervisory_faults,
            0
        );
        assert_eq!(
            planner
                .plan(&observation(&[Some(60); 3], one_fan))
                .consecutive_supervisory_faults,
            1
        );
    }

    #[test]
    fn emergency_latch_does_not_self_clear_on_a_later_cool_sample() {
        let good_fans = fans(&[(3, 45), (6, 45)]);
        let mut planner =
            S9StockThermalPlanner::new(S9StockThermalProfile::S9jRecovery20190630E531, 89, 100);
        let mut hot = observation(&[Some(90); 3], good_fans);
        hot.hard_protect_max_local_pcb_c = Some(90);
        assert_eq!(
            planner.plan(&hot).thermal_state,
            ThermalSafetyState::Emergency
        );
        let cool = planner.plan(&observation(&[Some(50); 3], good_fans));
        assert_eq!(cool.thermal_state, ThermalSafetyState::Emergency);
        assert_eq!(
            cool.cut_steps, None,
            "a latch is not a new actuator command"
        );
    }

    #[test]
    fn forged_i16_extremes_do_not_overflow_curve_arithmetic() {
        let good_fans = fans(&[(3, 45), (6, 45)]);
        let mut hot = S9StockThermalPlanner::new(
            S9StockThermalProfile::S9jRecovery20190630E531,
            i16::MIN,
            20,
        );
        let hot_plan = hot.plan(&observation(&[Some(i16::MAX); 3], good_fans));
        assert_eq!(hot_plan.vendor_observed_pwm_percent, 100);
        assert_eq!(hot_plan.thermal_state, ThermalSafetyState::NotReady);

        let mut cold = S9StockThermalPlanner::new(
            S9StockThermalProfile::S9jRecovery20190630E531,
            i16::MAX,
            100,
        );
        let cold_plan = cold.plan(&observation(&[Some(i16::MIN); 3], good_fans));
        assert_eq!(cold_plan.vendor_observed_pwm_percent, 100);
        assert_eq!(cold_plan.thermal_state, ThermalSafetyState::NotReady);
    }
}
