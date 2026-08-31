//! Pure, no-I/O admission contracts for unresolved S21-generation lanes.
//! Passive route evidence never grants electrical authority, and GPIO437
//! polarity is never inherited across board targets.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceState<T> {
    Verified(T),
    ObservedNotVerified(T),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainRoute {
    pub chain: u8,
    pub uart: &'static str,
    pub reset_gpio: u32,
    pub reset_active_low: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerKind {
    Pic1704DeclaredUnverified,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerObservation {
    pub source: &'static str,
    pub controller: &'static str,
    pub endpoint: Option<u8>,
    pub authority: &'static str,
}

pub const S21XP_CONTROLLER_OBSERVATIONS: [ControllerObservation; 1] = [ControllerObservation {
    source: "ePIC UMC OS 1.22.0 transcribed topology A3HB70501",
    controller: "PIC1704",
    endpoint: Some(0x20),
    authority: "vendor-declared topology only; ePIC bitstream/carrier caveats apply",
}];

pub const T21_CONTROLLER_OBSERVATIONS: [ControllerObservation; 2] = [
    ControllerObservation {
        source: "ePIC UMC OS 1.22.0 transcribed topology BHB68701/BHB68703",
        controller: "PIC1704",
        endpoint: Some(0x20),
        authority: "vendor-transcribed topology only; not a same-unit controller readback",
    },
    ControllerObservation {
        source: "VNish T21 Amlogic held rootfs",
        controller: "via-PIC path label",
        endpoint: None,
        authority: "software-path observation; exact PIC identity/protocol unresolved",
    },
];

pub const S21PLUS_CONTROLLER_OBSERVATIONS: [ControllerObservation; 2] = [
    ControllerObservation {
        source: "ePIC UMC OS topology registry",
        controller: "PIC1704",
        endpoint: Some(0x20),
        authority: "vendor-transcribed topology only",
    },
    ControllerObservation {
        source: "held VNish S21+ Amlogic corpus",
        controller: "NoPic/TAS5782 inheritance candidate",
        endpoint: None,
        authority: "conflicting family inference; explicitly refused",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftwarePowerObservation {
    pub gpio: u32,
    pub startup_value: Option<bool>,
    pub low_writer_present: bool,
    pub high_writer_present: bool,
    pub electrical_polarity_proven: bool,
    pub rail_decay_proven: bool,
}

pub const T21_SOFTWARE_POWER: SoftwarePowerObservation = SoftwarePowerObservation {
    gpio: 437,
    startup_value: Some(true),
    low_writer_present: true,
    high_writer_present: true,
    electrical_polarity_proven: false,
    rail_decay_proven: false,
};

pub const S21XP_SOFTWARE_POWER: SoftwarePowerObservation = SoftwarePowerObservation {
    gpio: 437,
    startup_value: None,
    low_writer_present: false,
    high_writer_present: false,
    electrical_polarity_proven: false,
    rail_decay_proven: false,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetEvidence {
    ActiveLowTransformObserved,
    Unknown,
}

pub fn reset_evidence(contract: &Contract) -> ResetEvidence {
    match contract.routes {
        EvidenceState::Verified(routes)
            if routes.len() == 3 && routes.iter().all(|route| route.reset_active_low) =>
        {
            ResetEvidence::ActiveLowTransformObserved
        }
        _ => ResetEvidence::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contract {
    pub target: &'static str,
    pub asic: &'static str,
    pub chains: u8,
    pub chips_per_chain: u16,
    pub routes: EvidenceState<&'static [ChainRoute]>,
    pub controller: ControllerKind,
    pub controller_protocol: EvidenceState<&'static str>,
    pub psu_protocol: EvidenceState<&'static str>,
    pub power_gpio: EvidenceState<u32>,
    pub energized_level: EvidenceState<bool>,
    pub safeoff_level: EvidenceState<bool>,
    pub safeoff_readback: EvidenceState<&'static str>,
    pub cold_init_unwind: EvidenceState<&'static str>,
}

const AML_ROUTE: [ChainRoute; 3] = [
    ChainRoute {
        chain: 0,
        uart: "/dev/ttyS3",
        reset_gpio: 454,
        reset_active_low: true,
    },
    ChainRoute {
        chain: 1,
        uart: "/dev/ttyS2",
        reset_gpio: 455,
        reset_active_low: true,
    },
    ChainRoute {
        chain: 2,
        uart: "/dev/ttyS1",
        reset_gpio: 456,
        reset_active_low: true,
    },
];

const fn unresolved(
    target: &'static str,
    asic: &'static str,
    chips: u16,
    routes: EvidenceState<&'static [ChainRoute]>,
    controller: ControllerKind,
    gpio: EvidenceState<u32>,
) -> Contract {
    Contract {
        target,
        asic,
        chains: 3,
        chips_per_chain: chips,
        routes,
        controller,
        controller_protocol: EvidenceState::Unknown,
        psu_protocol: EvidenceState::Unknown,
        power_gpio: gpio,
        energized_level: EvidenceState::Unknown,
        safeoff_level: EvidenceState::Unknown,
        safeoff_readback: EvidenceState::Unknown,
        cold_init_unwind: EvidenceState::Unknown,
    }
}

pub const S21XP_AML: Contract = unresolved(
    "am3-s21xp",
    "BM1370",
    91,
    EvidenceState::Verified(&AML_ROUTE),
    ControllerKind::Pic1704DeclaredUnverified,
    EvidenceState::ObservedNotVerified(437),
);
pub const T21_AML: Contract = unresolved(
    "am3-t21",
    "BM1368",
    108,
    EvidenceState::Verified(&AML_ROUTE),
    ControllerKind::Unknown,
    EvidenceState::ObservedNotVerified(437),
);
pub const S21PLUS_AML: Contract = unresolved(
    "amlogic-s21plus",
    "BM1370",
    55,
    EvidenceState::Unknown,
    ControllerKind::Unknown,
    EvidenceState::Unknown,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocker {
    Route,
    ControllerIdentity,
    ControllerProtocol,
    PsuProtocol,
    PowerPolarity,
    SafeOffReadback,
    ColdInitUnwind,
}

/// Exact identity carried by every electrical observation.  Marketing family
/// names and a shared GPIO number are deliberately insufficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElectricalTarget<'a> {
    pub board_target: &'a str,
    pub control_board_revision: &'a str,
    pub hashboard_revision: &'a str,
    pub psu_model: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RailSample<'a> {
    pub target: ElectricalTarget<'a>,
    pub commanded_gpio_level: bool,
    pub gpio_readback_level: bool,
    pub rail_mv: u32,
    pub elapsed_ms: u32,
}

/// Physical polarity result.  This can only be produced from a paired,
/// same-unit measurement; held software observations cannot construct it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedPowerPolarity<'a> {
    pub target: ElectricalTarget<'a>,
    pub energized_level: bool,
    pub safeoff_level: bool,
    pub energized_rail_mv: u32,
    pub safeoff_rail_mv: u32,
    pub safeoff_decay_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolarityEvidenceError {
    TargetMismatch,
    CommandReadbackMismatch,
    SameLevel,
    EnergizedRailTooLow,
    SafeOffRailTooHigh,
    SafeOffDecayTooSlow,
}

/// Conservative acceptance bounds for a no-work bench measurement.  These
/// are evidence-quality thresholds, not nominal PSU regulation limits.
pub const MIN_ENERGIZED_RAIL_MV: u32 = 8_000;
pub const MAX_SAFEOFF_RAIL_MV: u32 = 1_000;
pub const MAX_SAFEOFF_DECAY_MS: u32 = 5_000;

pub fn verify_power_polarity<'a>(
    energized: RailSample<'a>,
    safeoff: RailSample<'a>,
) -> Result<VerifiedPowerPolarity<'a>, PolarityEvidenceError> {
    if energized.target != safeoff.target {
        return Err(PolarityEvidenceError::TargetMismatch);
    }
    if energized.commanded_gpio_level != energized.gpio_readback_level
        || safeoff.commanded_gpio_level != safeoff.gpio_readback_level
    {
        return Err(PolarityEvidenceError::CommandReadbackMismatch);
    }
    if energized.commanded_gpio_level == safeoff.commanded_gpio_level {
        return Err(PolarityEvidenceError::SameLevel);
    }
    if energized.rail_mv < MIN_ENERGIZED_RAIL_MV {
        return Err(PolarityEvidenceError::EnergizedRailTooLow);
    }
    if safeoff.rail_mv > MAX_SAFEOFF_RAIL_MV {
        return Err(PolarityEvidenceError::SafeOffRailTooHigh);
    }
    if safeoff.elapsed_ms > MAX_SAFEOFF_DECAY_MS {
        return Err(PolarityEvidenceError::SafeOffDecayTooSlow);
    }
    Ok(VerifiedPowerPolarity {
        target: energized.target,
        energized_level: energized.commanded_gpio_level,
        safeoff_level: safeoff.commanded_gpio_level,
        energized_rail_mv: energized.rail_mv,
        safeoff_rail_mv: safeoff.rail_mv,
        safeoff_decay_ms: safeoff.elapsed_ms,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdInitStage {
    NeverEnergized,
    CoolingAdmitted,
    RailEnergized,
    ResetReleased,
    ChainsInitialized,
    WorkEnabled,
    Quiesced,
    SafeOffVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwindError {
    WorkNotQuiesced,
    MissingPhysicalSafeOff,
}

/// Pure admission model for the required unwind order.  It intentionally has
/// no GPIO/I2C/UART executor; target-specific owners must supply those only
/// after exact controller and polarity admission closes.
pub fn admit_cold_init_unwind(
    stage: ColdInitStage,
    work_quiesced: bool,
    physical_safeoff: Option<&VerifiedPowerPolarity<'_>>,
) -> Result<ColdInitStage, UnwindError> {
    if matches!(
        stage,
        ColdInitStage::NeverEnergized | ColdInitStage::CoolingAdmitted
    ) {
        return Ok(ColdInitStage::NeverEnergized);
    }
    if !work_quiesced {
        return Err(UnwindError::WorkNotQuiesced);
    }
    if physical_safeoff.is_none() {
        return Err(UnwindError::MissingPhysicalSafeOff);
    }
    Ok(ColdInitStage::SafeOffVerified)
}

impl Contract {
    pub fn blockers(&self) -> Vec<Blocker> {
        let mut out = Vec::new();
        if !matches!(self.routes, EvidenceState::Verified(_)) {
            out.push(Blocker::Route);
        }
        // A declaration is intentionally not a verified physical identity.
        out.push(Blocker::ControllerIdentity);
        if !matches!(self.controller_protocol, EvidenceState::Verified(_)) {
            out.push(Blocker::ControllerProtocol);
        }
        if !matches!(self.psu_protocol, EvidenceState::Verified(_)) {
            out.push(Blocker::PsuProtocol);
        }
        if !matches!(self.energized_level, EvidenceState::Verified(_))
            || !matches!(self.safeoff_level, EvidenceState::Verified(_))
        {
            out.push(Blocker::PowerPolarity);
        }
        if !matches!(self.safeoff_readback, EvidenceState::Verified(_)) {
            out.push(Blocker::SafeOffReadback);
        }
        if !matches!(self.cold_init_unwind, EvidenceState::Verified(_)) {
            out.push(Blocker::ColdInitUnwind);
        }
        out
    }
    pub fn executable(&self) -> bool {
        self.blockers().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routes_do_not_grant_power() {
        for c in [S21XP_AML, T21_AML] {
            assert!(matches!(c.routes, EvidenceState::Verified(_)));
            assert!(!c.executable());
            assert!(c.blockers().contains(&Blocker::PowerPolarity));
        }
    }
    #[test]
    fn plus_does_not_inherit_a_carrier() {
        assert!(matches!(S21PLUS_AML.routes, EvidenceState::Unknown));
        assert!(matches!(S21PLUS_AML.power_gpio, EvidenceState::Unknown));
        assert!(S21PLUS_AML.blockers().contains(&Blocker::Route));
    }
    #[test]
    fn gpio_observation_is_not_polarity() {
        for c in [S21XP_AML, T21_AML] {
            assert_eq!(c.power_gpio, EvidenceState::ObservedNotVerified(437));
            assert!(matches!(c.safeoff_level, EvidenceState::Unknown));
        }
        assert_eq!(T21_SOFTWARE_POWER.startup_value, Some(true));
        assert!(!T21_SOFTWARE_POWER.electrical_polarity_proven);
        assert!(!T21_SOFTWARE_POWER.rail_decay_proven);
    }
    #[test]
    fn controller_declarations_never_close_identity() {
        assert_eq!(S21XP_CONTROLLER_OBSERVATIONS[0].endpoint, Some(0x20));
        assert_eq!(T21_CONTROLLER_OBSERVATIONS.len(), 2);
        assert_eq!(S21PLUS_CONTROLLER_OBSERVATIONS.len(), 2);
        for contract in [S21XP_AML, T21_AML, S21PLUS_AML] {
            assert!(contract.blockers().contains(&Blocker::ControllerIdentity));
        }
    }
    #[test]
    fn reset_transform_is_observation_not_unwind() {
        assert_eq!(
            reset_evidence(&S21XP_AML),
            ResetEvidence::ActiveLowTransformObserved
        );
        assert_eq!(
            reset_evidence(&T21_AML),
            ResetEvidence::ActiveLowTransformObserved
        );
        assert_eq!(reset_evidence(&S21PLUS_AML), ResetEvidence::Unknown);
        assert!(S21XP_AML.blockers().contains(&Blocker::ColdInitUnwind));
    }

    fn target<'a>(board_target: &'a str) -> ElectricalTarget<'a> {
        ElectricalTarget {
            board_target,
            control_board_revision: "A113D-revision-from-unit",
            hashboard_revision: "revision-from-eeprom",
            psu_model: "model-from-nameplate-and-query",
        }
    }

    #[test]
    fn physical_polarity_requires_same_exact_target_and_readback() {
        let on = RailSample {
            target: target("am3-t21"),
            commanded_gpio_level: true,
            gpio_readback_level: true,
            rail_mv: 12_100,
            elapsed_ms: 250,
        };
        let off = RailSample {
            target: target("am3-t21"),
            commanded_gpio_level: false,
            gpio_readback_level: false,
            rail_mv: 120,
            elapsed_ms: 900,
        };
        let proof = verify_power_polarity(on, off).expect("same-unit polarity proof");
        assert!(proof.energized_level);
        assert!(!proof.safeoff_level);

        let s19k = RailSample {
            target: target("am3-s19k"),
            ..off
        };
        assert_eq!(
            verify_power_polarity(on, s19k),
            Err(PolarityEvidenceError::TargetMismatch)
        );
    }

    #[test]
    fn cold_init_unwind_is_fail_closed_after_energization() {
        assert_eq!(
            admit_cold_init_unwind(ColdInitStage::RailEnergized, true, None),
            Err(UnwindError::MissingPhysicalSafeOff)
        );
        assert_eq!(
            admit_cold_init_unwind(ColdInitStage::WorkEnabled, false, None),
            Err(UnwindError::WorkNotQuiesced)
        );
        assert_eq!(
            admit_cold_init_unwind(ColdInitStage::CoolingAdmitted, false, None),
            Ok(ColdInitStage::NeverEnergized)
        );
    }
}
