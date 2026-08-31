//! Immersion daemon-WIRING contract (Round-15 A3 follow-up).
//!
//! The five `[thermal.immersion]` tests in `src/config.rs` are RESOLVER
//! tests: they call `cfg.thermal.immersion.decide(true)` with a hard-coded
//! argument, so they cannot see what production actually passes
//!.
//! Nothing pinned the daemon's actual wiring — deleting the
//! `enable_immersion` call in `daemon.rs`, flipping the caller's
//! `platform_looks_air_cooled` choice, or dropping the fan-write
//! `immersion_active()` gates failed no test. This source contract extracts
//! the caller's actual choices from `src/daemon.rs` and pins them.
//!
//! NOTE (self-match trap, ):
//! this file pins a DIFFERENT file (`daemon.rs`), so the needles below cannot
//! be satisfied by this test's own source. Needles are kept as single exact
//! literals of the production lines.

const DAEMON_SRC: &str = include_str!("../src/daemon.rs");

/// The daemon must actually arm immersion on the production controller with
/// the production-captured config + platform choice — not a test-local pair.
#[test]
fn daemon_arms_immersion_on_the_production_controller() {
    assert!(
        DAEMON_SRC.contains(
            "controller.enable_immersion(&thermal_immersion_cfg, thermal_platform_looks_air_cooled);"
        ),
        "daemon.rs no longer calls enable_immersion with the captured config + \
         platform choice — the immersion capability would silently become an \
         orphan (config accepted, controller never armed). If the wiring was \
         intentionally moved, update this pin to the new call site."
    );
    assert!(
        DAEMON_SRC.contains("sup.enable_immersion("),
        "daemon.rs must also arm the thermal supervisor's immersion offset"
    );
    // The config the call consumes must be captured from the daemon's own
    // parsed config, not constructed ad hoc.
    assert!(
        DAEMON_SRC.contains("let thermal_immersion_cfg = self.config.thermal.immersion.clone();"),
        "daemon.rs no longer captures [thermal.immersion] from the parsed \
         config for the controller-arming call."
    );
}

/// The caller's extracted choice: every current control board (am1-s9 / am2 /
/// am3-bb / am3-aml) is an air-cooled chassis, so the daemon passes
/// `platform_looks_air_cooled = true`. That makes `enabled = true` WITHOUT
/// the explicit acknowledgement fail closed (RefusedAirCooled — fans stay
/// managed). Flipping this to `false` would let a bare `enabled = true`
/// bypass fan management on an air-cooled unit, which cooks boards.
#[test]
fn daemon_platform_choice_is_air_cooled_true() {
    assert!(
        DAEMON_SRC.contains("let thermal_platform_looks_air_cooled = true;"),
        "daemon.rs no longer passes platform_looks_air_cooled = true. On the \
         current all-air-cooled fleet this choice is what makes a bare \
         [thermal.immersion] enabled=true REFUSE (fail-closed) without the \
         operator's acknowledge_air_cooled_override. Changing it requires a \
         declared per-board cooling medium (dcentrald_common::cooling_medium), \
         never a blanket flip."
    );
}

/// Both HAL fan-write arms (SetFanPwm + ThrottleAndFan) must stay gated on
/// `!controller.immersion_active()` — the daemon-side half of "no fan command
/// reaches hardware on an immersion rig".
#[test]
fn daemon_fan_writes_are_gated_on_immersion_active() {
    let gate_count = DAEMON_SRC
        .matches("if !controller.immersion_active() {")
        .count();
    assert!(
        gate_count >= 2,
        "expected >= 2 fan-write arms gated on !controller.immersion_active() \
         in daemon.rs (SetFanPwm + ThrottleAndFan), found {gate_count} — a \
         removed gate lets a fan command reach hardware while immersion is \
         active (or, if the gates were refactored, update this pin)."
    );
}
