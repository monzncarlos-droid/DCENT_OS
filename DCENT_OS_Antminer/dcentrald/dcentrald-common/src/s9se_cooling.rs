//! Ctrl_C43 / S9 SE cooling contract (GitHub DCENT_OS#2).
//!
//! Stock FPGA still has a fan PWM register and a tach register. On the
//! reported S9 SE Ctrl_C43 those registers are **not a cooling loop**:
//!
//! - `FAN_CONTROL` (`axi[33]` / `0x84`) accepts writes.
//! - `FAN_SPEED` (`axi[1]` / `0x04`) always reads 0.
//! - 4-wire Noctuas **stop** when the PWM pin is connected and run at
//!   100 % with pin 4 lifted. Independent of firmware.
//!
//! A future `am1-s9se` tuner/supervisor MUST consume this module:
//! tach=0 is not `FanFailure`, PWM is not an airflow knob, and thermal
//! safety is temperature + hash-cut only. This file is host-testable
//! policy. It does not open `/dev/axi_fpga_dev` and does not admit a
//! board.

/// Stock FPGA fan PWM byte offset (`set_fan_control` → `axi[33]`).
pub const FAN_CONTROL_OFFSET: u32 = 0x084;
/// Stock FPGA tach byte offset (`get_fan_speed` → `axi[1]`).
pub const FAN_SPEED_OFFSET: u32 = 0x004;

/// How the 4-wire PWM pin is wired on the reported unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SePwmPinWiring {
    /// Pin 4 lifted: Noctuas run 100 %. PWM register writes do nothing
    /// on the wire.
    Pin4LiftedFullSpeed,
    /// PWM pin connected: Noctuas **stop**. Do not "fix" silence by
    /// connecting this pin under load.
    PwmPinConnectedStopped,
}

/// Why a Ctrl_C43 fan sample is not thermal evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeFanSampleKind {
    /// `0x84` write landed in the FPGA (readback may match) but air
    /// does not follow PWM.
    PwmWriteAcceptedNoAirflow,
    /// `0x04` is 0. On this board that is the idle register, not a
    /// stalled fan.
    TachAlwaysZeroNotEvidence,
}

/// Admission of one fan sample on a declared S9 SE / Ctrl_C43.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeFanAdmission {
    /// Sample recorded. Must not become `FanFailure` or a PWM raise.
    EvidenceUnavailable { kind: S9SeFanSampleKind },
}

/// Tuner / supervisor action requested for cooling or noise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeCoolingAction {
    RaisePwm,
    LowerPwm,
    CutHash,
}

/// Why a cooling action is refused or allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeCoolingDecision {
    /// PWM is not an actuator on this board.
    RefusePwmNotAnActuator,
    /// Hash-cut is the only software cooling/noise tool.
    AllowHashCut,
}

/// Static contract: FPGA fan registers exist, they are not a loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9SeCoolingContract {
    pub pwm_register_accepts_writes: bool,
    pub pwm_affects_airflow: bool,
    pub tach_is_evidence: bool,
    pub treat_tach_zero_as_fan_failure: bool,
    pub tach_available_for_supervisor: bool,
}

/// The #2 live Ctrl_C43 contract.
pub const CTRL_C43_S9SE_COOLING: S9SeCoolingContract = S9SeCoolingContract {
    pwm_register_accepts_writes: true,
    pwm_affects_airflow: false,
    tach_is_evidence: false,
    treat_tach_zero_as_fan_failure: false,
    tach_available_for_supervisor: false,
};

/// Classify a tach/PWM sample. Callers that already know the board is
/// Ctrl_C43 / S9 SE must use this instead of "PWM>0 && RPM==0 ⇒ stall".
pub fn admit_s9se_fan_sample(commanded_pwm: u8, tach_reg_low8: u8) -> S9SeFanAdmission {
    let _ = commanded_pwm;
    if tach_reg_low8 == 0 {
        return S9SeFanAdmission::EvidenceUnavailable {
            kind: S9SeFanSampleKind::TachAlwaysZeroNotEvidence,
        };
    }
    // A non-zero tach on this board would be surprising; still do not
    // treat PWM as the cause. Record as "write accepted, no airflow
    // proof" until a second live unit shows a working tach.
    let _ = tach_reg_low8;
    S9SeFanAdmission::EvidenceUnavailable {
        kind: S9SeFanSampleKind::PwmWriteAcceptedNoAirflow,
    }
}

/// Stock `set_PWM`: clamp 5..=100, then
/// `((50*pct/100) << 16) | (50*(100-pct)/100)`.
/// Packing is not an airflow permit on Ctrl_C43.
pub const PWM_MIN_PERCENT: u8 = 5;
pub const PWM_MAX_PERCENT: u8 = 100;
pub const PWM_FPGA_STEPS: u32 = 50;

pub fn clamp_stock_pwm_percent(pwm_percent: u8) -> u8 {
    if pwm_percent <= 4 {
        PWM_MIN_PERCENT
    } else if pwm_percent > PWM_MAX_PERCENT {
        PWM_MAX_PERCENT
    } else {
        pwm_percent
    }
}

pub fn pack_fan_control_word(pwm_percent: u8) -> u32 {
    let pct = u32::from(clamp_stock_pwm_percent(pwm_percent));
    let high = PWM_FPGA_STEPS * pct / 100;
    let low = PWM_FPGA_STEPS * (100 - pct) / 100;
    (high << 16) | low
}

/// `disable_hash_board` clears DHASH run bit `0x40` after PIC DAC disable.
pub fn hash_cut_dhash_word(previous: u32) -> u32 {
    previous & !0x40
}

/// Tuner policy: PWM raise/lower is refused; hash-cut is allowed.
pub fn decide_s9se_cooling_action(action: S9SeCoolingAction) -> S9SeCoolingDecision {
    match action {
        S9SeCoolingAction::RaisePwm | S9SeCoolingAction::LowerPwm => {
            S9SeCoolingDecision::RefusePwmNotAnActuator
        }
        S9SeCoolingAction::CutHash => S9SeCoolingDecision::AllowHashCut,
    }
}

/// Connecting the PWM pin under the #2 wiring **stops** the Noctuas.
/// Software must not instruct that as a quiet-home fix.
pub fn pwm_pin_connect_is_safe(_wiring: S9SePwmPinWiring) -> bool {
    false
}

/// Supervisor hook: `am1-s9se` must not treat tach=0 as a stall.
/// Other targets return `None` so the caller keeps its own default.
pub fn supervisor_tach_available_for_target(board_target: &str) -> Option<bool> {
    if board_target == "am1-s9se" {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_match_stock_fpga_fan_map() {
        assert_eq!(FAN_CONTROL_OFFSET, 0x084);
        assert_eq!(FAN_SPEED_OFFSET, 0x004);
        assert_eq!(FAN_CONTROL_OFFSET, 33 * 4);
        assert_eq!(FAN_SPEED_OFFSET, 1 * 4);
    }

    #[test]
    fn contract_says_pwm_and_tach_are_not_a_loop() {
        let c = CTRL_C43_S9SE_COOLING;
        assert!(c.pwm_register_accepts_writes);
        assert!(!c.pwm_affects_airflow);
        assert!(!c.tach_is_evidence);
        assert!(!c.treat_tach_zero_as_fan_failure);
        assert!(!c.tach_available_for_supervisor);
    }

    #[test]
    fn tach_zero_with_pwm_commanded_is_not_fan_failure() {
        let sample = admit_s9se_fan_sample(30, 0);
        assert_eq!(
            sample,
            S9SeFanAdmission::EvidenceUnavailable {
                kind: S9SeFanSampleKind::TachAlwaysZeroNotEvidence
            }
        );
        assert!(!CTRL_C43_S9SE_COOLING.treat_tach_zero_as_fan_failure);
    }

    #[test]
    fn tuner_must_not_use_pwm_as_a_knob() {
        assert_eq!(
            decide_s9se_cooling_action(S9SeCoolingAction::RaisePwm),
            S9SeCoolingDecision::RefusePwmNotAnActuator
        );
        assert_eq!(
            decide_s9se_cooling_action(S9SeCoolingAction::LowerPwm),
            S9SeCoolingDecision::RefusePwmNotAnActuator
        );
        assert_eq!(
            decide_s9se_cooling_action(S9SeCoolingAction::CutHash),
            S9SeCoolingDecision::AllowHashCut
        );
    }

    #[test]
    fn connecting_pwm_pin_is_never_a_software_fix() {
        assert!(!pwm_pin_connect_is_safe(S9SePwmPinWiring::Pin4LiftedFullSpeed));
        assert!(!pwm_pin_connect_is_safe(
            S9SePwmPinWiring::PwmPinConnectedStopped
        ));
    }

    #[test]
    fn am1_s9se_supervisor_has_no_tach() {
        assert_eq!(supervisor_tach_available_for_target("am1-s9se"), Some(false));
        assert_eq!(supervisor_tach_available_for_target("am1-s9"), None);
    }

    #[test]
    fn stock_pwm_word_is_clamped_and_not_an_actuator() {
        assert_eq!(clamp_stock_pwm_percent(0), 5);
        assert_eq!(clamp_stock_pwm_percent(100), 100);
        assert_eq!(pack_fan_control_word(100), 0x0032_0000);
        assert_eq!(pack_fan_control_word(50), 0x0019_0019);
        assert_eq!(hash_cut_dhash_word(0xFFFF_FFFF), 0xFFFF_FFBF);
        assert_eq!(
            decide_s9se_cooling_action(S9SeCoolingAction::RaisePwm),
            S9SeCoolingDecision::RefusePwmNotAnActuator
        );
    }
}
