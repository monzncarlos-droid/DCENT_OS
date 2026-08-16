//! Release- and model-scoped BM1396 enumeration lifecycle contract.
//!
//! This pure planner records the ordered behavior recovered from four held
//! S17e/T17e `bmminer` images. It performs no I/O, carries no observation
//! provenance, and grants no carrier, rail, or work-dispatch authority.
//!
//! Evidence:
//! - 2019 S17e SHA-256
//!   `2947e3c2007f56a3494675d34cb98604488970498653e946860e48ef15ea6206`,
//!   startup/enumeration caller `0x105e0`;
//! - 2019 T17e SHA-256
//!   `48a6a939b50ea00840aea4e9a17714f7fd28a59cb622e4975be81a13686145ab`,
//!   startup/enumeration caller `0x17998`;
//! - signed 2020 S17e SHA-256
//!   `819bd5ee790f3ce74f61a45546856e0cd7b37a62e7ec2263ebb83e35220c8243`,
//!   caller `0x13a14`, enumeration function `0x82958`; and
//! - signed 2020 T17e SHA-256
//!   `d0f14d843e35b15ffdf73d3523fa637ac318ade6c1a660764ceab5a48e135ffe`,
//!   caller `0x16958`, enumeration function `0x83800`.

use crate::bm1396_contract::{
    bm1396_t17e_next_retry_voltage_cv, Bm1396Model, BM1396_FPGA_CHAIN_SLOT_COUNT,
    BM1396_VENDOR_WORKING_VOLTAGE_MAX_CV, BM1396_VENDOR_WORKING_VOLTAGE_MIN_CV,
};

pub const BM1396_LEGACY_2019_ENUMERATION_MAX_ATTEMPTS: u8 = 3;
pub const BM1396_LEGACY_2019_SHORT_COUNT_MAX_RETRIES: u8 = 2;
pub const BM1396_LEGACY_2019_ENUMERATION_MAXIMUM_PASSES: u8 = 1;
pub const BM1396_SIGNED_2020_ENUMERATION_MAX_ATTEMPTS: u8 = 4;
pub const BM1396_SIGNED_2020_SHORT_COUNT_MAX_RETRIES: u8 = 3;
pub const BM1396_S17E_SIGNED_2020_ENUMERATION_MAXIMUM_PASSES: u8 = 1;
pub const BM1396_T17E_SIGNED_2020_ENUMERATION_MAXIMUM_PASSES: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396FirmwareRelease {
    Legacy2019,
    Signed2020,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396EnumerationProfile {
    /// Upper bound on passes entered by the recovered caller. Error gates and
    /// terminal chain mismatches can return before a pass or slot scan completes.
    pub maximum_passes: u8,
    pub maximum_attempts_per_chain_per_pass: u8,
    pub maximum_retries_per_chain_per_pass: u8,
    pub t17e_retry_voltage_ramp: bool,
}

/// Resolve the exact bounded loop geometry for one held release/model pair.
pub const fn bm1396_enumeration_profile(
    release: Bm1396FirmwareRelease,
    model: Bm1396Model,
) -> Bm1396EnumerationProfile {
    match release {
        Bm1396FirmwareRelease::Legacy2019 => Bm1396EnumerationProfile {
            maximum_passes: BM1396_LEGACY_2019_ENUMERATION_MAXIMUM_PASSES,
            maximum_attempts_per_chain_per_pass: BM1396_LEGACY_2019_ENUMERATION_MAX_ATTEMPTS,
            maximum_retries_per_chain_per_pass: BM1396_LEGACY_2019_SHORT_COUNT_MAX_RETRIES,
            t17e_retry_voltage_ramp: false,
        },
        Bm1396FirmwareRelease::Signed2020 => Bm1396EnumerationProfile {
            maximum_passes: match model {
                Bm1396Model::S17e => BM1396_S17E_SIGNED_2020_ENUMERATION_MAXIMUM_PASSES,
                Bm1396Model::T17e => BM1396_T17E_SIGNED_2020_ENUMERATION_MAXIMUM_PASSES,
            },
            maximum_attempts_per_chain_per_pass: BM1396_SIGNED_2020_ENUMERATION_MAX_ATTEMPTS,
            maximum_retries_per_chain_per_pass: BM1396_SIGNED_2020_SHORT_COUNT_MAX_RETRIES,
            t17e_retry_voltage_ramp: matches!(model, Bm1396Model::T17e),
        },
    }
}

/// Operations performed once when the caller enters a 2020 chain pass.
///
/// The 2019 binaries have no equivalent global preamble: their chain-bit
/// assertion and three-second sleep are repeated inside every attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396EnumerationPassStep {
    AssertAllPresentFpgaChainBits,
    DelayCallValue(u32),
    ApplySteppedWorkingVoltage,
    SetUart115200,
}

pub const BM1396_SIGNED_2020_ENUMERATION_PASS_START: &[Bm1396EnumerationPassStep] = &[
    Bm1396EnumerationPassStep::AssertAllPresentFpgaChainBits,
    Bm1396EnumerationPassStep::DelayCallValue(3_000),
    Bm1396EnumerationPassStep::ApplySteppedWorkingVoltage,
    Bm1396EnumerationPassStep::SetUart115200,
    Bm1396EnumerationPassStep::DelayCallValue(10),
];

pub const fn bm1396_enumeration_pass_start(
    release: Bm1396FirmwareRelease,
) -> &'static [Bm1396EnumerationPassStep] {
    match release {
        Bm1396FirmwareRelease::Legacy2019 => &[],
        Bm1396FirmwareRelease::Signed2020 => BM1396_SIGNED_2020_ENUMERATION_PASS_START,
    }
}

/// Hardware-facing spine between the two possible signed-2020 T17e passes.
///
/// Gate variants require a zero return before proceeding and propagate the
/// original nonzero value. The fixed-VCO frequency helper's return is
/// explicitly discarded by stock; the pure plan records that weakness but
/// grants no rail, PLL, or carrier authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396T17e2020InterPassStep {
    ApplyHighestConfiguredVoltageBySteps,
    ReinitializeAsicAndGateDomainAdcMode1PropagateNonzero,
    GateBringupTemperatureAndPropagateNonzero {
        minimum_pcb_temperature_c: i16,
    },
    DelayCallValue(u32),
    SetAsicAndFpgaBaud {
        baud: u32,
    },
    /// Update reported/status metadata from the selected auto-adapt profile.
    /// This is not an operational PLL write or an input to the following ramp.
    LoadAutoAdaptFrequencyMetadata {
        fallback_reported_mhz: u16,
    },
    /// Before each PLL stage, stock may select and apply a stepped board-rail
    /// target from a frequency-band/PCB-temperature lookup. That lookup is a
    /// separately tracked unresolved contract and this plan is non-executable.
    IncrementFrequencyWithFixedVcoAndSteppedRailResultDiscarded {
        chain_mask: u8,
        pll_bank_selector_source: Bm1396PllBankSelectorSource,
        voltage_target_source: Bm1396InterPassVoltageTargetSource,
        target_mhz: u16,
        higher_voltage: bool,
    },
    GateDomainAdcMode1PropagateNonzero,
    AdvanceDomainAdcThresholdIndex,
    AdvancePassCounterAndRestartScan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396PllBankSelectorSource {
    /// Runtime shared byte; zero-initialized in the exact image and without a
    /// recovered direct writer. Values 0..=3 select registers 08/60/64/68.
    SharedAutoAdaptByte,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396InterPassVoltageTargetSource {
    /// Exact signed-2020 T17e calibration-interpolated, right-closed
    /// frequency/PCB-minimum lookup. The pure planner remains non-authoritative.
    Signed2020T17eAutoAdaptPlanner,
}

pub const BM1396_T17E_SIGNED_2020_INTER_PASS_TRANSITION: &[Bm1396T17e2020InterPassStep] = &[
    Bm1396T17e2020InterPassStep::ApplyHighestConfiguredVoltageBySteps,
    Bm1396T17e2020InterPassStep::ReinitializeAsicAndGateDomainAdcMode1PropagateNonzero,
    Bm1396T17e2020InterPassStep::GateBringupTemperatureAndPropagateNonzero {
        minimum_pcb_temperature_c: -10,
    },
    Bm1396T17e2020InterPassStep::DelayCallValue(10),
    Bm1396T17e2020InterPassStep::SetAsicAndFpgaBaud { baud: 3_000_000 },
    Bm1396T17e2020InterPassStep::DelayCallValue(10),
    Bm1396T17e2020InterPassStep::LoadAutoAdaptFrequencyMetadata {
        fallback_reported_mhz: 300,
    },
    Bm1396T17e2020InterPassStep::IncrementFrequencyWithFixedVcoAndSteppedRailResultDiscarded {
        chain_mask: 0xff,
        pll_bank_selector_source: Bm1396PllBankSelectorSource::SharedAutoAdaptByte,
        voltage_target_source: Bm1396InterPassVoltageTargetSource::Signed2020T17eAutoAdaptPlanner,
        target_mhz: 300,
        higher_voltage: true,
    },
    Bm1396T17e2020InterPassStep::DelayCallValue(500),
    Bm1396T17e2020InterPassStep::GateDomainAdcMode1PropagateNonzero,
    Bm1396T17e2020InterPassStep::AdvanceDomainAdcThresholdIndex,
    Bm1396T17e2020InterPassStep::AdvancePassCounterAndRestartScan,
];

/// Return the one recovered inter-pass transition, if the release/model has it.
pub const fn bm1396_inter_pass_transition(
    release: Bm1396FirmwareRelease,
    model: Bm1396Model,
) -> Option<&'static [Bm1396T17e2020InterPassStep]> {
    match (release, model) {
        (Bm1396FirmwareRelease::Signed2020, Bm1396Model::T17e) => {
            Some(BM1396_T17E_SIGNED_2020_INTER_PASS_TRANSITION)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396EnumerationAttemptStep {
    AssertFpgaChainBit { slot: u8 },
    SleepSeconds(u32),
    EnableDcDcPicCommand15 { slot: u8 },
    DelayCallValue(u32),
    ClearFpgaChainBit { slot: u8 },
    BroadcastRegister58 { slot: u8, value: u32 },
    Enumerate { slot: u8 },
    ResetPicApplicationPath { slot: u8 },
    SetRequestedWorkingVoltageCv(u16),
    ApplySteppedWorkingVoltage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396EnumerationAttemptOutcome {
    Accepted,
    Retry {
        next_attempt_index: u8,
        next_working_voltage_cv: Option<u16>,
    },
    /// The bounded attempt loop is exhausted. This is not a fatality claim:
    /// signed-2020 T17e stock can continue to inter-pass or even return success.
    Exhausted {
        final_working_voltage_cv: Option<u16>,
    },
}

/// Exact comparison class used by the recovered caller after attempt
/// exhaustion. Value one is known as scan-user mode in signed-2020 T17e;
/// the older binaries are kept observational because that name was not proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396RuntimeModeClass {
    ModeOne,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396PostExhaustionStep {
    DisableDcDcPicCommand15 {
        slot: u8,
    },
    ClearChainActiveFlag {
        slot: u8,
    },
    DecrementActiveChainCount,
    /// Signed-2020 helper accepts an eight-bit mask and only visits slots 0..7,
    /// then clears three shared recovery words even when the mask is zero.
    ApplyEightSlotIsolationHelper {
        selected_mask: u8,
    },
    PrepareGlobalError {
        class: u8,
        detail: u8,
    },
    RouteError {
        code: u8,
    },
    ContinueSlotScan,
    EnterInterPassTransition,
    Return(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396PassCompletionDisposition {
    EnterInterPassTransition,
    Return(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396PostExhaustionDisposition {
    ContinueSlotScan {
        on_pass_completion: Bm1396PassCompletionDisposition,
    },
    EnterInterPassTransition,
    Return(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396PostExhaustionPlan {
    pub release: Bm1396FirmwareRelease,
    pub model: Bm1396Model,
    pub pass_index: u8,
    pub slot: u8,
    pub runtime_mode: Bm1396RuntimeModeClass,
    pub active_chains_before: u8,
    pub active_chains_after: u8,
    pub steps: Vec<Bm1396PostExhaustionStep>,
    pub disposition: Bm1396PostExhaustionDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396EnumerationAttemptPlan {
    pub release: Bm1396FirmwareRelease,
    pub model: Bm1396Model,
    pub pass_index: u8,
    pub attempt_index: u8,
    pub slot: u8,
    pub expected_responses: u16,
    pub observed_responses: u16,
    pub steps: Vec<Bm1396EnumerationAttemptStep>,
    pub outcome: Bm1396EnumerationAttemptOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396LifecyclePlanError {
    InvalidChainSlot { observed: u8 },
    InvalidPassIndex { observed: u8, maximum_passes: u8 },
    InvalidAttemptIndex { observed: u8, maximum_attempts: u8 },
    MissingT17eWorkingVoltage,
    T17eWorkingVoltageOutsideVendorEnvelope { observed_cv: u16 },
    InvalidActiveChainCount { observed: u8 },
}

impl std::fmt::Display for Bm1396LifecyclePlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidChainSlot { observed } => write!(
                f,
                "BM1396 chain slot {observed} is outside the 16-slot FPGA bitmap"
            ),
            Self::InvalidPassIndex {
                observed,
                maximum_passes,
            } => write!(
                f,
                "BM1396 enumeration pass {observed} is outside maximum {maximum_passes}"
            ),
            Self::InvalidAttemptIndex {
                observed,
                maximum_attempts,
            } => write!(
                f,
                "BM1396 enumeration attempt {observed} is outside maximum {maximum_attempts}"
            ),
            Self::MissingT17eWorkingVoltage => write!(
                f,
                "signed-2020 T17e enumeration requires the current vendor working voltage"
            ),
            Self::T17eWorkingVoltageOutsideVendorEnvelope { observed_cv } => write!(
                f,
                "signed-2020 T17e working voltage {observed_cv} cV is outside the recovered 1800..=2100 cV vendor envelope"
            ),
            Self::InvalidActiveChainCount { observed } => write!(
                f,
                "BM1396 active-chain count {observed} is outside 1..=16"
            ),
        }
    }
}

/// Plan the caller-level behavior after the final per-chain attempt fails.
///
/// This is separate from [`plan_bm1396_enumeration_attempt`] because the
/// caller's mode, pass index, and active-chain count determine whether stock
/// continues, enters T17e inter-pass logic, or returns. Several stock branches
/// return success after routing error 9; the plan records that behavior but no
/// clean executor should treat it as successful hardware admission.
pub fn plan_bm1396_post_exhaustion(
    release: Bm1396FirmwareRelease,
    model: Bm1396Model,
    pass_index: u8,
    slot: u8,
    runtime_mode: Bm1396RuntimeModeClass,
    active_chains_before: u8,
) -> Result<Bm1396PostExhaustionPlan, Bm1396LifecyclePlanError> {
    if slot >= BM1396_FPGA_CHAIN_SLOT_COUNT {
        return Err(Bm1396LifecyclePlanError::InvalidChainSlot { observed: slot });
    }
    if !(1..=BM1396_FPGA_CHAIN_SLOT_COUNT).contains(&active_chains_before) {
        return Err(Bm1396LifecyclePlanError::InvalidActiveChainCount {
            observed: active_chains_before,
        });
    }
    let profile = bm1396_enumeration_profile(release, model);
    if pass_index >= profile.maximum_passes {
        return Err(Bm1396LifecyclePlanError::InvalidPassIndex {
            observed: pass_index,
            maximum_passes: profile.maximum_passes,
        });
    }

    let mut steps = Vec::new();
    let active_chains_after = match release {
        Bm1396FirmwareRelease::Legacy2019 => {
            steps.extend([
                Bm1396PostExhaustionStep::DisableDcDcPicCommand15 { slot },
                Bm1396PostExhaustionStep::ClearChainActiveFlag { slot },
                Bm1396PostExhaustionStep::DecrementActiveChainCount,
            ]);
            active_chains_before - 1
        }
        Bm1396FirmwareRelease::Signed2020 => {
            let selected_mask = if slot < 8 { 1_u8 << slot } else { 0 };
            steps.push(Bm1396PostExhaustionStep::ApplyEightSlotIsolationHelper { selected_mask });
            active_chains_before - u8::from(selected_mask != 0)
        }
    };

    let pass_completion =
        if matches!(model, Bm1396Model::T17e) && pass_index + 1 < profile.maximum_passes {
            Bm1396PassCompletionDisposition::EnterInterPassTransition
        } else {
            Bm1396PassCompletionDisposition::Return(match release {
                Bm1396FirmwareRelease::Legacy2019 => -1,
                Bm1396FirmwareRelease::Signed2020 => 0,
            })
        };

    let disposition = match (release, runtime_mode) {
        (Bm1396FirmwareRelease::Legacy2019, Bm1396RuntimeModeClass::Other) => {
            steps.extend([
                Bm1396PostExhaustionStep::PrepareGlobalError {
                    class: 1,
                    detail: 0xff,
                },
                Bm1396PostExhaustionStep::RouteError { code: 9 },
                Bm1396PostExhaustionStep::Return(-1),
            ]);
            Bm1396PostExhaustionDisposition::Return(-1)
        }
        (Bm1396FirmwareRelease::Legacy2019, Bm1396RuntimeModeClass::ModeOne) => {
            steps.push(Bm1396PostExhaustionStep::ContinueSlotScan);
            Bm1396PostExhaustionDisposition::ContinueSlotScan {
                on_pass_completion: Bm1396PassCompletionDisposition::Return(-1),
            }
        }
        (Bm1396FirmwareRelease::Signed2020, Bm1396RuntimeModeClass::ModeOne)
            if active_chains_after == 0 =>
        {
            steps.push(Bm1396PostExhaustionStep::Return(-1));
            Bm1396PostExhaustionDisposition::Return(-1)
        }
        (Bm1396FirmwareRelease::Signed2020, Bm1396RuntimeModeClass::ModeOne) => {
            steps.push(Bm1396PostExhaustionStep::ContinueSlotScan);
            Bm1396PostExhaustionDisposition::ContinueSlotScan {
                on_pass_completion: pass_completion,
            }
        }
        (Bm1396FirmwareRelease::Signed2020, Bm1396RuntimeModeClass::Other) => {
            steps.extend([
                Bm1396PostExhaustionStep::PrepareGlobalError {
                    class: 1,
                    detail: 0xff,
                },
                Bm1396PostExhaustionStep::RouteError { code: 9 },
            ]);
            match pass_completion {
                Bm1396PassCompletionDisposition::EnterInterPassTransition => {
                    steps.push(Bm1396PostExhaustionStep::EnterInterPassTransition);
                    Bm1396PostExhaustionDisposition::EnterInterPassTransition
                }
                Bm1396PassCompletionDisposition::Return(code) => {
                    steps.push(Bm1396PostExhaustionStep::Return(code));
                    Bm1396PostExhaustionDisposition::Return(code)
                }
            }
        }
    };

    Ok(Bm1396PostExhaustionPlan {
        release,
        model,
        pass_index,
        slot,
        runtime_mode,
        active_chains_before,
        active_chains_after,
        steps,
        disposition,
    })
}

impl std::error::Error for Bm1396LifecyclePlanError {}

/// Plan one exact per-chain enumeration attempt and its mismatch tail.
///
/// Attempt and pass indexes are zero-based. `current_working_voltage_cv` is
/// required only by signed-2020 T17e, whose caller reads it before the attempt
/// loop and advances it after every mismatch. The advance/reset/reapply tail is
/// emitted even after attempt index 3, immediately before exhaustion. This
/// intentionally preserves a surprising stock side effect without granting an
/// executor permission to perform it.
pub fn plan_bm1396_enumeration_attempt(
    release: Bm1396FirmwareRelease,
    model: Bm1396Model,
    pass_index: u8,
    attempt_index: u8,
    slot: u8,
    observed_responses: u16,
    current_working_voltage_cv: Option<u16>,
) -> Result<Bm1396EnumerationAttemptPlan, Bm1396LifecyclePlanError> {
    if slot >= BM1396_FPGA_CHAIN_SLOT_COUNT {
        return Err(Bm1396LifecyclePlanError::InvalidChainSlot { observed: slot });
    }

    let profile = bm1396_enumeration_profile(release, model);
    if pass_index >= profile.maximum_passes {
        return Err(Bm1396LifecyclePlanError::InvalidPassIndex {
            observed: pass_index,
            maximum_passes: profile.maximum_passes,
        });
    }
    if attempt_index >= profile.maximum_attempts_per_chain_per_pass {
        return Err(Bm1396LifecyclePlanError::InvalidAttemptIndex {
            observed: attempt_index,
            maximum_attempts: profile.maximum_attempts_per_chain_per_pass,
        });
    }

    let current_working_voltage_cv = if profile.t17e_retry_voltage_ramp {
        let voltage = current_working_voltage_cv
            .ok_or(Bm1396LifecyclePlanError::MissingT17eWorkingVoltage)?;
        if !(BM1396_VENDOR_WORKING_VOLTAGE_MIN_CV..=BM1396_VENDOR_WORKING_VOLTAGE_MAX_CV)
            .contains(&voltage)
        {
            return Err(
                Bm1396LifecyclePlanError::T17eWorkingVoltageOutsideVendorEnvelope {
                    observed_cv: voltage,
                },
            );
        }
        Some(voltage)
    } else {
        None
    };

    let mut steps = Vec::new();
    match release {
        Bm1396FirmwareRelease::Legacy2019 => {
            steps.extend([
                Bm1396EnumerationAttemptStep::AssertFpgaChainBit { slot },
                Bm1396EnumerationAttemptStep::SleepSeconds(3),
                Bm1396EnumerationAttemptStep::EnableDcDcPicCommand15 { slot },
                Bm1396EnumerationAttemptStep::DelayCallValue(1_000),
                Bm1396EnumerationAttemptStep::ClearFpgaChainBit { slot },
                Bm1396EnumerationAttemptStep::DelayCallValue(200),
                Bm1396EnumerationAttemptStep::Enumerate { slot },
            ]);
        }
        Bm1396FirmwareRelease::Signed2020 => {
            steps.extend([
                Bm1396EnumerationAttemptStep::EnableDcDcPicCommand15 { slot },
                Bm1396EnumerationAttemptStep::DelayCallValue(1_000),
                Bm1396EnumerationAttemptStep::ClearFpgaChainBit { slot },
                Bm1396EnumerationAttemptStep::DelayCallValue(200),
                Bm1396EnumerationAttemptStep::BroadcastRegister58 {
                    slot,
                    value: 0x0777_7777,
                },
                Bm1396EnumerationAttemptStep::Enumerate { slot },
            ]);
        }
    }

    let expected_responses = model.expected_chips_per_present_chain();
    let outcome = if observed_responses == expected_responses {
        Bm1396EnumerationAttemptOutcome::Accepted
    } else {
        steps.push(Bm1396EnumerationAttemptStep::ResetPicApplicationPath { slot });

        let next_working_voltage_cv = if profile.t17e_retry_voltage_ramp {
            steps.push(Bm1396EnumerationAttemptStep::AssertFpgaChainBit { slot });
            let current_voltage = current_working_voltage_cv
                .ok_or(Bm1396LifecyclePlanError::MissingT17eWorkingVoltage)?;
            let voltage = bm1396_t17e_next_retry_voltage_cv(current_voltage);
            steps.extend([
                Bm1396EnumerationAttemptStep::SetRequestedWorkingVoltageCv(voltage),
                Bm1396EnumerationAttemptStep::ApplySteppedWorkingVoltage,
            ]);
            Some(voltage)
        } else {
            if matches!(release, Bm1396FirmwareRelease::Signed2020) {
                steps.push(Bm1396EnumerationAttemptStep::AssertFpgaChainBit { slot });
            }
            None
        };

        if attempt_index + 1 < profile.maximum_attempts_per_chain_per_pass {
            Bm1396EnumerationAttemptOutcome::Retry {
                next_attempt_index: attempt_index + 1,
                next_working_voltage_cv,
            }
        } else {
            Bm1396EnumerationAttemptOutcome::Exhausted {
                final_working_voltage_cv: next_working_voltage_cv,
            }
        }
    };

    Ok(Bm1396EnumerationAttemptPlan {
        release,
        model,
        pass_index,
        attempt_index,
        slot,
        expected_responses,
        observed_responses,
        steps,
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_and_model_profiles_pin_attempt_retry_and_pass_counts() {
        for model in [Bm1396Model::S17e, Bm1396Model::T17e] {
            assert_eq!(
                bm1396_enumeration_profile(Bm1396FirmwareRelease::Legacy2019, model),
                Bm1396EnumerationProfile {
                    maximum_passes: 1,
                    maximum_attempts_per_chain_per_pass: 3,
                    maximum_retries_per_chain_per_pass: 2,
                    t17e_retry_voltage_ramp: false,
                }
            );
        }
        assert_eq!(
            bm1396_enumeration_profile(Bm1396FirmwareRelease::Signed2020, Bm1396Model::S17e),
            Bm1396EnumerationProfile {
                maximum_passes: 1,
                maximum_attempts_per_chain_per_pass: 4,
                maximum_retries_per_chain_per_pass: 3,
                t17e_retry_voltage_ramp: false,
            }
        );
        assert_eq!(
            bm1396_enumeration_profile(Bm1396FirmwareRelease::Signed2020, Bm1396Model::T17e),
            Bm1396EnumerationProfile {
                maximum_passes: 2,
                maximum_attempts_per_chain_per_pass: 4,
                maximum_retries_per_chain_per_pass: 3,
                t17e_retry_voltage_ramp: true,
            }
        );
    }

    #[test]
    fn legacy_attempt_repeats_assert_and_three_second_sleep_but_terminal_tail_only_resets_pic() {
        let first = plan_bm1396_enumeration_attempt(
            Bm1396FirmwareRelease::Legacy2019,
            Bm1396Model::T17e,
            0,
            0,
            2,
            77,
            None,
        )
        .unwrap();
        assert_eq!(
            first.steps,
            vec![
                Bm1396EnumerationAttemptStep::AssertFpgaChainBit { slot: 2 },
                Bm1396EnumerationAttemptStep::SleepSeconds(3),
                Bm1396EnumerationAttemptStep::EnableDcDcPicCommand15 { slot: 2 },
                Bm1396EnumerationAttemptStep::DelayCallValue(1_000),
                Bm1396EnumerationAttemptStep::ClearFpgaChainBit { slot: 2 },
                Bm1396EnumerationAttemptStep::DelayCallValue(200),
                Bm1396EnumerationAttemptStep::Enumerate { slot: 2 },
                Bm1396EnumerationAttemptStep::ResetPicApplicationPath { slot: 2 },
            ]
        );
        assert_eq!(
            first.outcome,
            Bm1396EnumerationAttemptOutcome::Retry {
                next_attempt_index: 1,
                next_working_voltage_cv: None,
            }
        );

        let terminal = plan_bm1396_enumeration_attempt(
            Bm1396FirmwareRelease::Legacy2019,
            Bm1396Model::T17e,
            0,
            2,
            2,
            77,
            None,
        )
        .unwrap();
        assert_eq!(
            terminal.steps.last(),
            Some(&Bm1396EnumerationAttemptStep::ResetPicApplicationPath { slot: 2 })
        );
        assert!(!terminal.steps.iter().any(|step| matches!(
            step,
            Bm1396EnumerationAttemptStep::SetRequestedWorkingVoltageCv(_)
                | Bm1396EnumerationAttemptStep::ApplySteppedWorkingVoltage
        )));
        assert_eq!(
            terminal.outcome,
            Bm1396EnumerationAttemptOutcome::Exhausted {
                final_working_voltage_cv: None,
            }
        );
    }

    #[test]
    fn signed_2020_pass_preamble_is_outside_per_chain_retry_attempt() {
        assert!(bm1396_enumeration_pass_start(Bm1396FirmwareRelease::Legacy2019).is_empty());
        assert_eq!(
            bm1396_enumeration_pass_start(Bm1396FirmwareRelease::Signed2020),
            &[
                Bm1396EnumerationPassStep::AssertAllPresentFpgaChainBits,
                Bm1396EnumerationPassStep::DelayCallValue(3_000),
                Bm1396EnumerationPassStep::ApplySteppedWorkingVoltage,
                Bm1396EnumerationPassStep::SetUart115200,
                Bm1396EnumerationPassStep::DelayCallValue(10),
            ]
        );

        let retry = plan_bm1396_enumeration_attempt(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::S17e,
            0,
            1,
            0,
            134,
            None,
        )
        .unwrap();
        assert!(!retry
            .steps
            .contains(&Bm1396EnumerationAttemptStep::SleepSeconds(3)));
        assert_eq!(
            &retry.steps[retry.steps.len() - 2..],
            &[
                Bm1396EnumerationAttemptStep::ResetPicApplicationPath { slot: 0 },
                Bm1396EnumerationAttemptStep::AssertFpgaChainBit { slot: 0 },
            ]
        );
    }

    #[test]
    fn only_signed_2020_t17e_has_the_checked_inter_pass_transition() {
        for pair in [
            (Bm1396FirmwareRelease::Legacy2019, Bm1396Model::S17e),
            (Bm1396FirmwareRelease::Legacy2019, Bm1396Model::T17e),
            (Bm1396FirmwareRelease::Signed2020, Bm1396Model::S17e),
        ] {
            assert_eq!(bm1396_inter_pass_transition(pair.0, pair.1), None);
        }

        assert_eq!(
            bm1396_inter_pass_transition(Bm1396FirmwareRelease::Signed2020, Bm1396Model::T17e),
            Some(BM1396_T17E_SIGNED_2020_INTER_PASS_TRANSITION)
        );
        assert_eq!(
            BM1396_T17E_SIGNED_2020_INTER_PASS_TRANSITION,
            &[
                Bm1396T17e2020InterPassStep::ApplyHighestConfiguredVoltageBySteps,
                Bm1396T17e2020InterPassStep::ReinitializeAsicAndGateDomainAdcMode1PropagateNonzero,
                Bm1396T17e2020InterPassStep::GateBringupTemperatureAndPropagateNonzero {
                    minimum_pcb_temperature_c: -10,
                },
                Bm1396T17e2020InterPassStep::DelayCallValue(10),
                Bm1396T17e2020InterPassStep::SetAsicAndFpgaBaud { baud: 3_000_000 },
                Bm1396T17e2020InterPassStep::DelayCallValue(10),
                Bm1396T17e2020InterPassStep::LoadAutoAdaptFrequencyMetadata {
                    fallback_reported_mhz: 300,
                },
                Bm1396T17e2020InterPassStep::IncrementFrequencyWithFixedVcoAndSteppedRailResultDiscarded {
                    chain_mask: 0xff,
                    pll_bank_selector_source: Bm1396PllBankSelectorSource::SharedAutoAdaptByte,
                    voltage_target_source: Bm1396InterPassVoltageTargetSource::Signed2020T17eAutoAdaptPlanner,
                    target_mhz: 300,
                    higher_voltage: true,
                },
                Bm1396T17e2020InterPassStep::DelayCallValue(500),
                Bm1396T17e2020InterPassStep::GateDomainAdcMode1PropagateNonzero,
                Bm1396T17e2020InterPassStep::AdvanceDomainAdcThresholdIndex,
                Bm1396T17e2020InterPassStep::AdvancePassCounterAndRestartScan,
            ]
        );
    }

    #[test]
    fn signed_2020_t17e_terminal_mismatch_still_wraps_and_reapplies_voltage() {
        let terminal = plan_bm1396_enumeration_attempt(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::T17e,
            1,
            3,
            15,
            77,
            Some(2_100),
        )
        .unwrap();
        assert_eq!(terminal.expected_responses, 78);
        assert_eq!(
            &terminal.steps[terminal.steps.len() - 4..],
            &[
                Bm1396EnumerationAttemptStep::ResetPicApplicationPath { slot: 15 },
                Bm1396EnumerationAttemptStep::AssertFpgaChainBit { slot: 15 },
                Bm1396EnumerationAttemptStep::SetRequestedWorkingVoltageCv(1_800),
                Bm1396EnumerationAttemptStep::ApplySteppedWorkingVoltage,
            ]
        );
        assert_eq!(
            terminal.outcome,
            Bm1396EnumerationAttemptOutcome::Exhausted {
                final_working_voltage_cv: Some(1_800),
            }
        );
    }

    #[test]
    fn signed_2020_t17e_threads_voltage_across_all_mismatches_and_next_chain() {
        let mut voltage = 1_800;
        let mut emitted = Vec::new();

        for attempt in 0..4 {
            let plan = plan_bm1396_enumeration_attempt(
                Bm1396FirmwareRelease::Signed2020,
                Bm1396Model::T17e,
                0,
                attempt,
                0,
                77,
                Some(voltage),
            )
            .unwrap();
            let next = match plan.outcome {
                Bm1396EnumerationAttemptOutcome::Retry {
                    next_working_voltage_cv: Some(next),
                    ..
                }
                | Bm1396EnumerationAttemptOutcome::Exhausted {
                    final_working_voltage_cv: Some(next),
                } => next,
                other => panic!("unexpected mismatch outcome: {other:?}"),
            };
            emitted.push(next);
            voltage = next;
        }

        assert_eq!(emitted, [1_900, 2_000, 2_100, 1_800]);

        let next_chain = plan_bm1396_enumeration_attempt(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::T17e,
            0,
            0,
            1,
            77,
            Some(voltage),
        )
        .unwrap();
        assert_eq!(
            next_chain.outcome,
            Bm1396EnumerationAttemptOutcome::Retry {
                next_attempt_index: 1,
                next_working_voltage_cv: Some(1_900),
            }
        );
    }

    #[test]
    fn legacy_post_exhaustion_disables_chain_and_returns_failure_in_both_modes() {
        let other = plan_bm1396_post_exhaustion(
            Bm1396FirmwareRelease::Legacy2019,
            Bm1396Model::S17e,
            0,
            9,
            Bm1396RuntimeModeClass::Other,
            3,
        )
        .unwrap();
        assert_eq!(other.active_chains_after, 2);
        assert_eq!(
            other.steps,
            vec![
                Bm1396PostExhaustionStep::DisableDcDcPicCommand15 { slot: 9 },
                Bm1396PostExhaustionStep::ClearChainActiveFlag { slot: 9 },
                Bm1396PostExhaustionStep::DecrementActiveChainCount,
                Bm1396PostExhaustionStep::PrepareGlobalError {
                    class: 1,
                    detail: 0xff,
                },
                Bm1396PostExhaustionStep::RouteError { code: 9 },
                Bm1396PostExhaustionStep::Return(-1),
            ]
        );
        assert_eq!(
            other.disposition,
            Bm1396PostExhaustionDisposition::Return(-1)
        );

        let mode_one = plan_bm1396_post_exhaustion(
            Bm1396FirmwareRelease::Legacy2019,
            Bm1396Model::T17e,
            0,
            9,
            Bm1396RuntimeModeClass::ModeOne,
            3,
        )
        .unwrap();
        assert_eq!(
            mode_one.disposition,
            Bm1396PostExhaustionDisposition::ContinueSlotScan {
                on_pass_completion: Bm1396PassCompletionDisposition::Return(-1),
            }
        );
    }

    #[test]
    fn signed_2020_post_exhaustion_preserves_eight_slot_helper_and_stock_success_weakness() {
        let s17e = plan_bm1396_post_exhaustion(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::S17e,
            0,
            7,
            Bm1396RuntimeModeClass::Other,
            2,
        )
        .unwrap();
        assert_eq!(s17e.active_chains_after, 1);
        assert_eq!(
            s17e.steps[0],
            Bm1396PostExhaustionStep::ApplyEightSlotIsolationHelper {
                selected_mask: 0x80,
            }
        );
        assert_eq!(s17e.disposition, Bm1396PostExhaustionDisposition::Return(0));

        let high_slot = plan_bm1396_post_exhaustion(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::S17e,
            0,
            8,
            Bm1396RuntimeModeClass::Other,
            2,
        )
        .unwrap();
        assert_eq!(high_slot.active_chains_after, 2);
        assert_eq!(
            high_slot.steps[0],
            Bm1396PostExhaustionStep::ApplyEightSlotIsolationHelper { selected_mask: 0 }
        );

        let pass_one = plan_bm1396_post_exhaustion(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::T17e,
            0,
            0,
            Bm1396RuntimeModeClass::Other,
            2,
        )
        .unwrap();
        assert_eq!(
            pass_one.disposition,
            Bm1396PostExhaustionDisposition::EnterInterPassTransition
        );
        let pass_two = plan_bm1396_post_exhaustion(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::T17e,
            1,
            0,
            Bm1396RuntimeModeClass::Other,
            2,
        )
        .unwrap();
        assert_eq!(
            pass_two.disposition,
            Bm1396PostExhaustionDisposition::Return(0)
        );
    }

    #[test]
    fn signed_2020_mode_one_only_returns_failure_when_isolation_loses_last_chain() {
        let last = plan_bm1396_post_exhaustion(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::T17e,
            0,
            3,
            Bm1396RuntimeModeClass::ModeOne,
            1,
        )
        .unwrap();
        assert_eq!(last.active_chains_after, 0);
        assert_eq!(
            last.disposition,
            Bm1396PostExhaustionDisposition::Return(-1)
        );

        let retained = plan_bm1396_post_exhaustion(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::T17e,
            0,
            3,
            Bm1396RuntimeModeClass::ModeOne,
            2,
        )
        .unwrap();
        assert_eq!(
            retained.disposition,
            Bm1396PostExhaustionDisposition::ContinueSlotScan {
                on_pass_completion: Bm1396PassCompletionDisposition::EnterInterPassTransition,
            }
        );

        for count in [0, 17] {
            assert_eq!(
                plan_bm1396_post_exhaustion(
                    Bm1396FirmwareRelease::Signed2020,
                    Bm1396Model::T17e,
                    0,
                    0,
                    Bm1396RuntimeModeClass::ModeOne,
                    count,
                ),
                Err(Bm1396LifecyclePlanError::InvalidActiveChainCount { observed: count })
            );
        }
    }

    #[test]
    fn signed_2020_s17e_mode_one_continues_and_returns_zero_only_at_pass_completion() {
        let retained = plan_bm1396_post_exhaustion(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::S17e,
            0,
            3,
            Bm1396RuntimeModeClass::ModeOne,
            2,
        )
        .unwrap();

        assert_eq!(retained.active_chains_after, 1);
        assert_eq!(
            retained.steps,
            vec![
                Bm1396PostExhaustionStep::ApplyEightSlotIsolationHelper {
                    selected_mask: 0x08,
                },
                Bm1396PostExhaustionStep::ContinueSlotScan,
            ]
        );
        assert_eq!(
            retained.disposition,
            Bm1396PostExhaustionDisposition::ContinueSlotScan {
                on_pass_completion: Bm1396PassCompletionDisposition::Return(0),
            }
        );
    }

    #[test]
    fn signed_2020_high_slot_mode_one_zero_mask_keeps_active_count_and_continues() {
        let high_slot = plan_bm1396_post_exhaustion(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::T17e,
            0,
            8,
            Bm1396RuntimeModeClass::ModeOne,
            1,
        )
        .unwrap();

        assert_eq!(high_slot.active_chains_after, 1);
        assert_eq!(
            high_slot.steps,
            vec![
                Bm1396PostExhaustionStep::ApplyEightSlotIsolationHelper { selected_mask: 0 },
                Bm1396PostExhaustionStep::ContinueSlotScan,
            ]
        );
        assert_eq!(
            high_slot.disposition,
            Bm1396PostExhaustionDisposition::ContinueSlotScan {
                on_pass_completion: Bm1396PassCompletionDisposition::EnterInterPassTransition,
            }
        );
    }

    #[test]
    fn exact_count_accepts_without_any_reset_assert_or_voltage_tail() {
        let accepted = plan_bm1396_enumeration_attempt(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::T17e,
            1,
            0,
            3,
            78,
            Some(1_900),
        )
        .unwrap();
        assert_eq!(accepted.outcome, Bm1396EnumerationAttemptOutcome::Accepted);
        assert_eq!(
            accepted.steps.last(),
            Some(&Bm1396EnumerationAttemptStep::Enumerate { slot: 3 })
        );
    }

    #[test]
    fn planner_refuses_out_of_geometry_indexes_and_missing_or_unsafe_t17e_voltage() {
        let plan = |pass, attempt, slot, voltage| {
            plan_bm1396_enumeration_attempt(
                Bm1396FirmwareRelease::Signed2020,
                Bm1396Model::T17e,
                pass,
                attempt,
                slot,
                77,
                voltage,
            )
        };
        assert_eq!(
            plan(0, 0, 16, Some(1_800)),
            Err(Bm1396LifecyclePlanError::InvalidChainSlot { observed: 16 })
        );
        assert_eq!(
            plan(2, 0, 0, Some(1_800)),
            Err(Bm1396LifecyclePlanError::InvalidPassIndex {
                observed: 2,
                maximum_passes: 2,
            })
        );
        assert_eq!(
            plan(0, 4, 0, Some(1_800)),
            Err(Bm1396LifecyclePlanError::InvalidAttemptIndex {
                observed: 4,
                maximum_attempts: 4,
            })
        );
        assert_eq!(
            plan(0, 0, 0, None),
            Err(Bm1396LifecyclePlanError::MissingT17eWorkingVoltage)
        );
        assert_eq!(
            plan(0, 0, 0, Some(1_799)),
            Err(
                Bm1396LifecyclePlanError::T17eWorkingVoltageOutsideVendorEnvelope {
                    observed_cv: 1_799,
                }
            )
        );
        assert_eq!(
            plan(0, 0, 0, Some(2_101)),
            Err(
                Bm1396LifecyclePlanError::T17eWorkingVoltageOutsideVendorEnvelope {
                    observed_cv: 2_101,
                }
            )
        );
    }
}
