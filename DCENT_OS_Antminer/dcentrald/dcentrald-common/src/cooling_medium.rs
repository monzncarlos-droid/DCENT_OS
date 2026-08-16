//! Cooling-medium axis + declarative cut-ladder validation (Round-15 A3,
//!  axis 4 of
//! IMPLEMENTATION_QUEUE.md` §3).
//!
//! # Why this exists
//!
//! H3 found 27 hydro/immersion boards outside its own axis; the in-tree VNish
//! 1.2.7 registry (`dcentrald-silicon-profiles::vnish_thermal`, rank 31)
//! carries **25 immersion-only rows** whose `auto`/`manual` fan blocks are
//! genuinely absent (`None`, never defaulted). On such a board the house rule
//! **"cut hash power before raising fan noise" is undefined** — it degenerates
//! to "cut hash", and any fan-raise rung in the escalation ladder must be
//! **absent, not zero**: a "raise fans" rung on a fanless board is a no-op
//! that can *satisfy* the ladder while the board keeps cooking.
//!
//! This module supplies the missing axis as pure, HAL-free policy types:
//!
//! - [`CoolingMedium`] — `Air` / `Hydro` / `Immersion`. Undeclared is spelled
//!   `Option<CoolingMedium> = None` at every consumer; there is deliberately
//!   NO `Unknown` variant, so "unknown" can never be pattern-matched into a
//!   permissive arm by accident.
//! - [`CoolingClass`] — the safety-relevant projection (`ForcedAir` vs
//!   [`CoolingClass::ExternalLoop`]). Hydro vs Immersion is a *plumbing*
//!   distinction; both have **no chassis-fan actuator on the air path**.
//! - [`CutRung`] / cut-ladder validation ([`validate_cut_ladder`]) — the
//!   declarative form of the escalation ladder, with the two structural
//!   safety properties enforced fail-closed:
//!     1. the **terminal rung is a power cut** on every medium (fan raise is
//!        never the last resort), and every fan-raise rung is preceded by a
//!        hash-reducing rung (cut-before-noise, type-level per H5 §5.1);
//!     2. a board whose declared medium has **no fan actuator carries no
//!        [`CutRung::RaiseFansToCap`] rung at all** (absent, not zero).
//! - [`fan_bypass_permitted`] — the fail-closed gate for "may fan management
//!   be bypassed for this declared medium?".
//!
//! # The undeclared-medium direction (safety argument — do not flip)
//!
//! Neither projection of an undeclared medium is safe:
//!
//! - Undeclared → treated as fanless would **bypass fan management on a real
//!   air-cooled board** — boards cook with no airflow. Catastrophic.
//! - Undeclared → treated as `Air` *for bypass purposes* is safe (fans stay
//!   managed), but it must never **grant** a fan-raise rung the authority to
//!   stand in for a cut.
//!
//! So the rule is asymmetric, and each half takes the conservative side:
//!
//! - [`fan_bypass_permitted`]`(None) == false` — an undeclared medium NEVER
//!   bypasses fan management (identical to today's behaviour on every
//!   air-cooled board; mirrors `ImmersionConfig::decide`'s refusal in
//!   `dcentrald-thermal::immersion`).
//! - [`validate_cut_ladder`]`(None, …)` applies the **universal** rules
//!   (terminal cut + cut-before-noise) and *permits* fan rungs — because on
//!   an undeclared medium the fans must still be managed. A cut-only ladder
//!   (no fan rung) also passes for every medium: *absence* of fan raise is
//!   strictly more conservative, never less.
//!
//! # Evidence
//!
//! - Held VNish 1.2.7 firmware bytes: `hwscan` ELF (byte-identical across
//!   carriers, e.g.
//!   l9-cv/usr/bin/hwscan` @ 0x4185b8) carries exactly one `immersion`
//!   cooling-mode string; the 18-image model-JSON consensus (pinned in
//!   `dcentrald-silicon-profiles/src/vnish_thermal_matrix_1_2_7.json`) shows
//!   25 models declaring ONLY `immersion` with absent fan blocks.
//! - All 77 VNish rows *include* `immersion` in `cooling_modes` (air models
//!   declare `auto, manual, immersion`) — which is why
//!   [`cooling_class_from_mode_labels`] keys on "fan-curve modes present",
//!   NOT on "immersion present".
//! - Bitmain stock hydro BMU inner payloads (2023+ `S19Pro+-Hydro`,
//!   `S21Imm-AML`) are cipher-opaque (`0x26 0x01` magic, key not held) —
//!   stock-side corroboration is desk-blocked; recorded, not guessed.

/// Declared cooling medium of a board/unit.
///
/// **Declared, never inferred**: a consumer must only construct this from an
/// explicit declaration (registry row, operator config, catalog). Undeclared
/// is `Option<CoolingMedium> = None` — there is intentionally no `Unknown`
/// variant (see module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoolingMedium {
    /// Forced-air cooling: chassis fans on the airflow path. The only medium
    /// with a fan actuator the thermal ladder may command.
    Air,
    /// Water-block ("Hydro" / HHB-class) cooling: external pump + dry-cooler
    /// loop. No chassis-fan actuator on the air path.
    Hydro,
    /// Dielectric-fluid immersion. No chassis-fan actuator.
    Immersion,
}

/// The safety-relevant projection of [`CoolingMedium`]: does the thermal
/// ladder have a fan actuator to command?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoolingClass {
    /// Chassis fans exist; fan rungs are meaningful (within the quiet cap).
    ForcedAir,
    /// Cooling is an external loop (hydro/immersion). There is NO fan
    /// actuator: a fan-raise rung is a no-op that must be ABSENT from the
    /// ladder, and the only escalation is hash reduction / power cut.
    ExternalLoop,
}

impl CoolingMedium {
    /// Safety projection. `Hydro` and `Immersion` are both
    /// [`CoolingClass::ExternalLoop`] — the plumbing differs, the absent fan
    /// actuator does not.
    pub const fn cooling_class(self) -> CoolingClass {
        match self {
            CoolingMedium::Air => CoolingClass::ForcedAir,
            CoolingMedium::Hydro | CoolingMedium::Immersion => CoolingClass::ExternalLoop,
        }
    }

    /// `true` iff this medium has a chassis-fan actuator the ladder may
    /// command.
    pub const fn has_fan_actuator(self) -> bool {
        matches!(self.cooling_class(), CoolingClass::ForcedAir)
    }

    /// Exact-match label parse (`"air"` / `"hydro"` / `"immersion"`).
    /// Fail-closed: anything else — including case variants, `"water"`,
    /// `"hyd"`, empty — returns `None` (undeclared), never a nearest match.
    pub fn parse_label(label: &str) -> Option<CoolingMedium> {
        match label {
            "air" => Some(CoolingMedium::Air),
            "hydro" => Some(CoolingMedium::Hydro),
            "immersion" => Some(CoolingMedium::Immersion),
            _ => None,
        }
    }
}

/// Classify a declared cooling-*mode* label set (e.g. VNish `cooling_modes`)
/// into a [`CoolingClass`].
///
/// Key corpus fact this encodes (verified against the pinned 77-row VNish
/// registry): **every** model declares an `immersion` mode — air models ship
/// `auto, manual, immersion`; the 25 fan-curve-less boards ship ONLY
/// `immersion`. So the discriminator is *presence of a fan-curve mode*
/// (`auto` or `manual`), never *presence of `immersion`*.
///
/// Fail-closed rules:
/// - any unrecognized label ⇒ `None` (refuse to classify);
/// - empty set ⇒ `None`;
/// - `auto`/`manual` present ⇒ `Some(ForcedAir)` (a fan curve exists);
/// - exactly `immersion`-only ⇒ `Some(ExternalLoop)`.
///
/// This deliberately returns the *class*, not a [`CoolingMedium`]: mode
/// labels cannot distinguish Hydro from Immersion, and fabricating that
/// distinction is forbidden.
pub fn cooling_class_from_mode_labels<S: AsRef<str>>(labels: &[S]) -> Option<CoolingClass> {
    if labels.is_empty() {
        return None;
    }
    let mut has_fan_curve_mode = false;
    let mut has_immersion = false;
    for l in labels {
        match l.as_ref() {
            "auto" | "manual" => has_fan_curve_mode = true,
            "immersion" => has_immersion = true,
            // Unknown mode label: refuse to classify (fail closed).
            _ => return None,
        }
    }
    if has_fan_curve_mode {
        Some(CoolingClass::ForcedAir)
    } else if has_immersion {
        Some(CoolingClass::ExternalLoop)
    } else {
        None
    }
}

/// May fan *management* be bypassed (no fan ramp commanded) for this declared
/// medium?
///
/// Fail-closed in the only safe direction: `true` ONLY for an explicitly
/// declared external-loop medium. `None` (undeclared) and `Some(Air)` keep
/// fan management active — bypassing fans on a real air-cooled board cooks
/// it, so undeclared must never be granted the bypass. This is the same
/// posture as `ImmersionConfig::decide` refusing to activate on an
/// air-cooled-looking platform.
pub fn fan_bypass_permitted(declared: Option<CoolingMedium>) -> bool {
    matches!(
        declared.map(CoolingMedium::cooling_class),
        Some(CoolingClass::ExternalLoop)
    )
}

/// One rung of the declarative thermal escalation ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CutRung {
    /// Reduce hash frequency (heat at the source goes down).
    ThrottleHash,
    /// Advisory profile step-down (autotuner may decline; still a
    /// hash-reducing intent).
    StepProfileDown,
    /// Raise fans **up to the quiet-home cap** (`fan_max_pwm`, never 100 %).
    /// Only meaningful on [`CoolingClass::ForcedAir`]; must be ABSENT — not
    /// zero — on an external-loop board.
    RaiseFansToCap,
    /// Cut hash power (emergency shutdown of mining — the safety floor).
    CutHashPower,
    /// Power off a board entirely.
    PowerOffBoard,
}

impl CutRung {
    /// `true` for rungs that remove hash power outright — the only rungs
    /// allowed in terminal position.
    pub const fn is_power_cut(self) -> bool {
        matches!(self, CutRung::CutHashPower | CutRung::PowerOffBoard)
    }

    /// `true` for rungs that reduce heat at the source (throttle, step-down,
    /// or a full cut). These are the rungs that may precede a fan raise
    /// under cut-before-noise.
    pub const fn reduces_hash(self) -> bool {
        matches!(
            self,
            CutRung::ThrottleHash
                | CutRung::StepProfileDown
                | CutRung::CutHashPower
                | CutRung::PowerOffBoard
        )
    }

    /// `true` for the fan-raise rung.
    pub const fn is_fan_raise(self) -> bool {
        matches!(self, CutRung::RaiseFansToCap)
    }
}

/// Why [`validate_cut_ladder`] refused a ladder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CutLadderError {
    /// The ladder has no rungs — there is no escalation at all.
    EmptyLadder,
    /// The terminal (last-resort) rung is not a power cut. Fan raise or a
    /// mere throttle must never be the final answer to over-temp.
    TerminalRungNotACut { terminal: CutRung },
    /// A fan-raise rung appears before any hash-reducing rung — violates
    /// "cut hash power before raising fan noise".
    FanRaiseBeforeHashCut { position: usize },
    /// The declared medium has no fan actuator, but the ladder carries a
    /// fan-raise rung. On a fanless board the rung must be ABSENT, not zero:
    /// a no-op rung can satisfy the ladder while the board keeps heating.
    FanRungOnFanlessMedium { position: usize },
}

impl std::fmt::Display for CutLadderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CutLadderError::EmptyLadder => write!(f, "cut ladder is empty"),
            CutLadderError::TerminalRungNotACut { terminal } => write!(
                f,
                "terminal ladder rung {terminal:?} is not a power cut — the last resort must cut hash power"
            ),
            CutLadderError::FanRaiseBeforeHashCut { position } => write!(
                f,
                "fan-raise rung at position {position} precedes every hash-reducing rung — cut hash before raising fan noise"
            ),
            CutLadderError::FanRungOnFanlessMedium { position } => write!(
                f,
                "fan-raise rung at position {position} on a medium with no fan actuator — the rung must be absent, not zero"
            ),
        }
    }
}

impl std::error::Error for CutLadderError {}

/// Validate an escalation ladder against a declared cooling medium.
///
/// Universal rules (every medium, including undeclared `None`):
/// 1. the ladder is non-empty;
/// 2. the terminal rung is a power cut ([`CutRung::is_power_cut`]);
/// 3. every [`CutRung::RaiseFansToCap`] is preceded by at least one
///    hash-reducing rung (cut-before-noise, structural).
///
/// Medium-specific rule:
/// 4. a declared medium whose [`CoolingClass`] is
///    [`CoolingClass::ExternalLoop`] (no fan actuator) must carry **no**
///    fan-raise rung anywhere — absent, not zero.
///
/// Undeclared (`None`) direction: rules 1–3 apply, fan rungs are *permitted*
/// (fans must stay managed on a possibly-air board), and nothing about
/// `None` ever relaxes a rule — a cut-only ladder passes for every medium
/// because omitting the fan raise is strictly more conservative.
pub fn validate_cut_ladder(
    declared: Option<CoolingMedium>,
    ladder: &[CutRung],
) -> Result<(), CutLadderError> {
    let Some(terminal) = ladder.last().copied() else {
        return Err(CutLadderError::EmptyLadder);
    };
    if !terminal.is_power_cut() {
        return Err(CutLadderError::TerminalRungNotACut { terminal });
    }

    let fanless = matches!(
        declared.map(CoolingMedium::cooling_class),
        Some(CoolingClass::ExternalLoop)
    );

    let mut seen_hash_reduction = false;
    for (position, rung) in ladder.iter().copied().enumerate() {
        if rung.is_fan_raise() {
            if fanless {
                // Rule 4: absent, not zero, on a fanless medium.
                return Err(CutLadderError::FanRungOnFanlessMedium { position });
            }
            if !seen_hash_reduction {
                // Rule 3: cut hash before raising fan noise.
                return Err(CutLadderError::FanRaiseBeforeHashCut { position });
            }
        }
        if rung.reduces_hash() {
            seen_hash_reduction = true;
        }
    }
    Ok(())
}

/// Canonical DCENT ladder for a forced-air board: throttle (cut heat at the
/// source) → raise fans up to the quiet cap → cut hash power. Terminal rung
/// is a cut; the fan raise is preceded by a hash reduction.
pub const CANONICAL_FORCED_AIR_LADDER: &[CutRung] = &[
    CutRung::ThrottleHash,
    CutRung::RaiseFansToCap,
    CutRung::CutHashPower,
];

/// Canonical DCENT ladder for an external-loop (hydro/immersion) board:
/// throttle → cut hash power. NO fan rung — absent, not zero.
pub const CANONICAL_EXTERNAL_LOOP_LADDER: &[CutRung] =
    &[CutRung::ThrottleHash, CutRung::CutHashPower];

/// The canonical ladder for a cooling class.
pub const fn canonical_cut_ladder(class: CoolingClass) -> &'static [CutRung] {
    match class {
        CoolingClass::ForcedAir => CANONICAL_FORCED_AIR_LADDER,
        CoolingClass::ExternalLoop => CANONICAL_EXTERNAL_LOOP_LADDER,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- medium / class -------------------------------------------------

    #[test]
    fn cooling_class_projection() {
        assert_eq!(CoolingMedium::Air.cooling_class(), CoolingClass::ForcedAir);
        assert_eq!(
            CoolingMedium::Hydro.cooling_class(),
            CoolingClass::ExternalLoop
        );
        assert_eq!(
            CoolingMedium::Immersion.cooling_class(),
            CoolingClass::ExternalLoop
        );
        assert!(CoolingMedium::Air.has_fan_actuator());
        assert!(!CoolingMedium::Hydro.has_fan_actuator());
        assert!(!CoolingMedium::Immersion.has_fan_actuator());
    }

    #[test]
    fn parse_label_is_exact_match_fail_closed() {
        assert_eq!(CoolingMedium::parse_label("air"), Some(CoolingMedium::Air));
        assert_eq!(
            CoolingMedium::parse_label("hydro"),
            Some(CoolingMedium::Hydro)
        );
        assert_eq!(
            CoolingMedium::parse_label("immersion"),
            Some(CoolingMedium::Immersion)
        );
        for bad in ["Air", "AIR", "water", "hyd", "imm", "", "immersion "] {
            assert_eq!(CoolingMedium::parse_label(bad), None, "label {bad:?}");
        }
    }

    #[test]
    fn mode_label_classifier_keys_on_fan_curve_not_immersion() {
        // Air models in the VNish corpus declare auto+manual+immersion —
        // the presence of `immersion` must NOT classify them fanless.
        assert_eq!(
            cooling_class_from_mode_labels(&["auto", "manual", "immersion"]),
            Some(CoolingClass::ForcedAir)
        );
        // The 25 hydro/immersion rows declare ONLY immersion.
        assert_eq!(
            cooling_class_from_mode_labels(&["immersion"]),
            Some(CoolingClass::ExternalLoop)
        );
    }

    #[test]
    fn mode_label_classifier_fails_closed() {
        // Unknown labels refuse (even alongside known ones).
        assert_eq!(
            cooling_class_from_mode_labels(&["immersion", "via-mixed"]),
            None
        );
        assert_eq!(cooling_class_from_mode_labels(&["water"]), None);
        // Empty set refuses.
        assert_eq!(cooling_class_from_mode_labels::<&str>(&[]), None);
        // Case variants refuse (exact match only).
        assert_eq!(cooling_class_from_mode_labels(&["Immersion"]), None);
    }

    // ---- fan bypass gate ------------------------------------------------

    #[test]
    fn fan_bypass_only_for_declared_external_loop() {
        assert!(fan_bypass_permitted(Some(CoolingMedium::Hydro)));
        assert!(fan_bypass_permitted(Some(CoolingMedium::Immersion)));
        assert!(!fan_bypass_permitted(Some(CoolingMedium::Air)));
        // LOAD-BEARING: an undeclared medium must NEVER bypass fan
        // management — bypassing fans on a real air-cooled board cooks it.
        assert!(!fan_bypass_permitted(None));
    }

    // ---- ladder validation ----------------------------------------------

    #[test]
    fn canonical_ladders_validate() {
        assert_eq!(
            validate_cut_ladder(Some(CoolingMedium::Air), CANONICAL_FORCED_AIR_LADDER),
            Ok(())
        );
        assert_eq!(
            validate_cut_ladder(Some(CoolingMedium::Hydro), CANONICAL_EXTERNAL_LOOP_LADDER),
            Ok(())
        );
        assert_eq!(
            validate_cut_ladder(
                Some(CoolingMedium::Immersion),
                CANONICAL_EXTERNAL_LOOP_LADDER
            ),
            Ok(())
        );
        assert_eq!(
            canonical_cut_ladder(CoolingClass::ForcedAir),
            CANONICAL_FORCED_AIR_LADDER
        );
        assert_eq!(
            canonical_cut_ladder(CoolingClass::ExternalLoop),
            CANONICAL_EXTERNAL_LOOP_LADDER
        );
    }

    #[test]
    fn fanless_medium_refuses_any_fan_rung_absent_not_zero() {
        // The exact axis-4 hazard: an air-shaped ladder on a hydro board.
        for medium in [CoolingMedium::Hydro, CoolingMedium::Immersion] {
            let err = validate_cut_ladder(Some(medium), CANONICAL_FORCED_AIR_LADDER).unwrap_err();
            assert_eq!(
                err,
                CutLadderError::FanRungOnFanlessMedium { position: 1 },
                "medium {medium:?}"
            );
        }
        // Even a fan rung buried mid-ladder after cuts is refused.
        let ladder = [
            CutRung::ThrottleHash,
            CutRung::CutHashPower,
            CutRung::RaiseFansToCap,
            CutRung::PowerOffBoard,
        ];
        assert_eq!(
            validate_cut_ladder(Some(CoolingMedium::Immersion), &ladder),
            Err(CutLadderError::FanRungOnFanlessMedium { position: 2 })
        );
    }

    #[test]
    fn terminal_rung_must_be_a_cut_on_every_medium() {
        // Fan raise as the last resort is refused for air, fanless, AND
        // undeclared — "raise fans harder" is never the final answer.
        let ladder = [CutRung::ThrottleHash, CutRung::RaiseFansToCap];
        for declared in [
            None,
            Some(CoolingMedium::Air),
            Some(CoolingMedium::Hydro),
            Some(CoolingMedium::Immersion),
        ] {
            let err = validate_cut_ladder(declared, &ladder).unwrap_err();
            assert!(
                matches!(
                    err,
                    CutLadderError::TerminalRungNotACut {
                        terminal: CutRung::RaiseFansToCap
                    } | CutLadderError::FanRungOnFanlessMedium { .. }
                ),
                "declared {declared:?} got {err:?}"
            );
        }
        // A bare throttle terminal is also not a cut.
        assert_eq!(
            validate_cut_ladder(Some(CoolingMedium::Air), &[CutRung::ThrottleHash]),
            Err(CutLadderError::TerminalRungNotACut {
                terminal: CutRung::ThrottleHash
            })
        );
    }

    #[test]
    fn fan_raise_must_follow_a_hash_reduction() {
        // Fans-first ladders (the ePIC ordering — fans first, cut last) are
        // refused: cut hash before raising fan noise.
        let ladder = [
            CutRung::RaiseFansToCap,
            CutRung::ThrottleHash,
            CutRung::CutHashPower,
        ];
        assert_eq!(
            validate_cut_ladder(Some(CoolingMedium::Air), &ladder),
            Err(CutLadderError::FanRaiseBeforeHashCut { position: 0 })
        );
        // Same refusal on an undeclared medium (universal rule).
        assert_eq!(
            validate_cut_ladder(None, &ladder),
            Err(CutLadderError::FanRaiseBeforeHashCut { position: 0 })
        );
    }

    #[test]
    fn empty_ladder_is_refused() {
        assert_eq!(
            validate_cut_ladder(None, &[]),
            Err(CutLadderError::EmptyLadder)
        );
    }

    #[test]
    fn undeclared_medium_gets_air_rules_never_fanless_certification() {
        // Undeclared: the air-shaped canonical ladder passes (fans stay
        // managed) …
        assert_eq!(
            validate_cut_ladder(None, CANONICAL_FORCED_AIR_LADDER),
            Ok(())
        );
        // … and a cut-only ladder ALSO passes (strictly more conservative).
        assert_eq!(
            validate_cut_ladder(None, CANONICAL_EXTERNAL_LOOP_LADDER),
            Ok(())
        );
        // But undeclared never earns the fan-management bypass (see
        // fan_bypass_only_for_declared_external_loop).
        assert!(!fan_bypass_permitted(None));
    }

    #[test]
    fn cut_only_ladder_passes_for_every_medium() {
        for declared in [
            None,
            Some(CoolingMedium::Air),
            Some(CoolingMedium::Hydro),
            Some(CoolingMedium::Immersion),
        ] {
            assert_eq!(
                validate_cut_ladder(declared, CANONICAL_EXTERNAL_LOOP_LADDER),
                Ok(()),
                "declared {declared:?}"
            );
        }
    }
}
