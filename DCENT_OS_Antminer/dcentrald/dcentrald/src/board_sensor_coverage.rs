//! Report-only coverage accounting for the four per-board LM75A sensors on
//! AM2 hash boards (campaign rank 21 / SG-2).
//!
//! # What this closes
//!
//! Both AM2 thermal consumers — the hybrid mining path's `read_board_and_die`
//! and the daemon runtime heartbeat's per-board sample — folded four sensor
//! reads into a single `max` over whatever survived a plausibility window. A
//! failed read was an in-band sentinel (`-999.0`, or `NaN` from a
//! bare-protocol dsPIC) that the window rejected, so it vanished. The result:
//!
//! > a board where three of four sensors are silent reports exactly the same
//! > board temperature, with exactly the same confidence, as a board where all
//! > four answered.
//!
//! On a unit whose whole purpose is to sit in a house as a space heater, an
//! unwatched hot corner is the failure that matters. `am2-s19jpro-zynq` is a
//! public-beta tier, so this is a shipped surface, not a lab one.
//!
//! # What this deliberately does NOT do
//!
//! **Report-only.** Nothing here feeds a shutdown, a throttle, a fan
//! response, or any control decision. Two independent reasons:
//!
//! 1. `expected` has no declarative source yet. It is `LM75A_ADDRS.len()` — a
//!    hardcoded 4 — while the producer's own documentation says a sensor "may
//!    not be present". Until board topology declares how many sensors a given
//!    hash board actually carries, a board that legitimately ships three
//!    sensors would read as permanently degraded. Wiring that into a cut would
//!    power off healthy hardware.
//! 2. It has no live-hardware validation. Coverage numbers must be observed on
//!    real boards before anything is allowed to act on them.
//!
//! The follow-up, in order: declare per-board sensor counts, observe coverage
//! in the field, then decide a policy. [`SensorSweep::is_complete`] and
//! [`SensorSweep::known_cooler_than`] already implement the fail-closed
//! semantics that policy would need.
//!
//! # Why the two call sites still use different plausibility windows
//!
//! The hybrid path accepts `[-20, 125]` inclusive; the daemon heartbeat path
//! accepts `(-40, 125)` exclusive (SG-3). Unifying them changes which readings
//! a live thermal path accepts, which is a behavioural change on shipped
//! firmware that cannot be validated at the desk. Each site therefore keeps
//! its own window and applies it to *both* its temperature and its coverage,
//! so the two always agree locally. The divergence is pinned by test so it is
//! visible and cannot widen silently.

use dcentrald_silicon_profiles::sensor_topology::SensorSweep;

/// The AM2 hybrid mining path's plausibility window, inclusive on both ends.
pub const AM2_HYBRID_MIN_C: f32 = -20.0;
/// The AM2 hybrid mining path's plausibility window, inclusive on both ends.
pub const AM2_HYBRID_MAX_C: f32 = 125.0;

/// The daemon runtime-heartbeat path's plausibility window, exclusive on both
/// ends.
pub const DAEMON_HEARTBEAT_MIN_C: f32 = -40.0;
/// The daemon runtime-heartbeat path's plausibility window, exclusive on both
/// ends.
pub const DAEMON_HEARTBEAT_MAX_C: f32 = 125.0;

/// Apply the AM2 hybrid path's inclusive window to a raw sweep.
pub fn filter_hybrid_window(readings: [Option<f32>; 4]) -> [Option<f32>; 4] {
    readings.map(|reading| reading.filter(|t| (AM2_HYBRID_MIN_C..=AM2_HYBRID_MAX_C).contains(t)))
}

/// Apply the daemon heartbeat path's exclusive window to a raw sweep.
pub fn filter_heartbeat_window(readings: [Option<f32>; 4]) -> [Option<f32>; 4] {
    readings.map(|reading| {
        reading.filter(|t| *t > DAEMON_HEARTBEAT_MIN_C && *t < DAEMON_HEARTBEAT_MAX_C)
    })
}

/// Emit the coverage line for one board sweep.
///
/// Complete coverage logs at `debug` (it is the steady state and would
/// otherwise be noise); any shortfall logs at `warn` naming the controller,
/// the count and which sensor slots went dark, because that is the condition
/// an operator needs to see. A fully blind board is called out separately: its
/// reported temperature is not merely partial, it does not exist.
pub fn report_board_sensor_coverage(
    site: &'static str,
    controller_addr: u8,
    sensor_addrs: [u8; 4],
    readings: &[Option<f32>; 4],
    sweep: &SensorSweep,
) {
    if sweep.is_complete() {
        tracing::debug!(
            target: "board_sensor_coverage",
            site,
            controller = format_args!("0x{:02X}", controller_addr),
            covered = sweep.covered,
            expected = sweep.expected,
            hottest_c = ?sweep.hottest_c,
            "LM75A coverage complete",
        );
        return;
    }

    let dark: Vec<String> = readings
        .iter()
        .enumerate()
        .filter(|(_, reading)| reading.is_none())
        .map(|(slot, _)| format!("0x{:02X}", sensor_addrs[slot]))
        .collect();

    tracing::warn!(
        target: "board_sensor_coverage",
        site,
        controller = format_args!("0x{:02X}", controller_addr),
        covered = sweep.covered,
        expected = sweep.expected,
        unmeasured = %dark.join(","),
        hottest_c = ?sweep.hottest_c,
        "LM75A coverage INCOMPLETE — the reported board temperature describes \
         only the sensors that answered; the unmeasured corners are unknown, \
         not cool. Report-only: no thermal action is taken on this signal.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRS: [u8; 4] = [0x48, 0x49, 0x4A, 0x4B];

    fn sweep_of(readings: [Option<f32>; 4]) -> SensorSweep {
        SensorSweep::from_readings(&readings, ADDRS.len() as u16)
    }

    /// The four coverage states must stay distinguishable after windowing.
    #[test]
    fn coverage_states_survive_the_hybrid_window() {
        let full = sweep_of(filter_hybrid_window([
            Some(50.0),
            Some(62.0),
            Some(58.0),
            Some(61.0),
        ]));
        assert_eq!((full.covered, full.expected), (4, 4));
        assert!(full.is_complete());
        assert_eq!(full.hottest_c, Some(62.0));

        let three = sweep_of(filter_hybrid_window([
            Some(50.0),
            Some(62.0),
            None,
            Some(61.0),
        ]));
        assert_eq!(three.covered, 3);
        assert!(!three.is_complete());
        // The hottest reading is IDENTICAL to the complete case — the exact
        // collapse this accounting exists to make visible.
        assert_eq!(three.hottest_c, full.hottest_c);

        let one = sweep_of(filter_hybrid_window([None, Some(62.0), None, None]));
        assert_eq!(one.covered, 1);
        assert_eq!(one.hottest_c, full.hottest_c);

        let blind = sweep_of(filter_hybrid_window([None; 4]));
        assert_eq!(blind.covered, 0);
        assert!(!blind.is_complete());
        assert_eq!(blind.hottest_c, None);
    }

    /// `-999.0` is the legacy failed-read sentinel. Both windows must reject
    /// it, so it can never be counted as a covered sensor.
    #[test]
    fn legacy_minus_999_sentinel_is_rejected_by_both_windows() {
        let hybrid = sweep_of(filter_hybrid_window([
            Some(-999.0),
            Some(55.0),
            Some(56.0),
            Some(57.0),
        ]));
        assert_eq!(hybrid.covered, 3);
        assert_eq!(hybrid.hottest_c, Some(57.0));

        let heartbeat = sweep_of(filter_heartbeat_window([
            Some(-999.0),
            Some(55.0),
            Some(56.0),
            Some(57.0),
        ]));
        assert_eq!(heartbeat.covered, 3);
        assert_eq!(heartbeat.hottest_c, Some(57.0));
    }

    /// SG-3 pin. The two live windows genuinely differ, and this test states
    /// exactly where. If someone unifies them, this test must be updated
    /// deliberately — the divergence cannot widen or vanish unnoticed.
    ///
    /// The gap is `(-40, -20)`: accepted by the daemon heartbeat path,
    /// rejected by the hybrid path. Because both sites fold with `max`, a
    /// reading that cold can only ever be the reported temperature when EVERY
    /// sensor is that cold, so the divergence cannot suppress an overtemp
    /// trip — it changes coverage counting and the stale-temp path only.
    #[test]
    fn the_two_plausibility_windows_differ_only_in_the_documented_gap() {
        for cold in [-39.9f32, -30.0, -20.1] {
            assert_eq!(
                filter_hybrid_window([Some(cold), None, None, None])[0],
                None,
                "{cold} must be rejected by the hybrid window",
            );
            assert_eq!(
                filter_heartbeat_window([Some(cold), None, None, None])[0],
                Some(cold),
                "{cold} must be accepted by the heartbeat window",
            );
        }

        // Inclusive vs exclusive at the shared upper bound.
        assert_eq!(
            filter_hybrid_window([Some(125.0), None, None, None])[0],
            Some(125.0),
        );
        assert_eq!(
            filter_heartbeat_window([Some(125.0), None, None, None])[0],
            None,
        );

        // Everything in the normal mining band is treated identically.
        for normal in [-19.0f32, 0.0, 25.0, 62.5, 90.0, 124.9] {
            assert_eq!(
                filter_hybrid_window([Some(normal), None, None, None])[0],
                filter_heartbeat_window([Some(normal), None, None, None])[0],
                "{normal} must be treated identically by both windows",
            );
        }
    }

    /// Over-coverage must never read as complete, and a board declaring no
    /// sensors has nothing to be complete about. Mutation guard: if
    /// `is_complete` were relaxed from `==` to `>=`, the first assertion here
    /// fails.
    #[test]
    fn completeness_is_equality_not_a_threshold() {
        let over = SensorSweep::from_readings(&[Some(50.0), Some(51.0), Some(52.0)], 2);
        assert!(
            !over.is_complete(),
            "3 covered against 2 expected must NOT read as complete",
        );

        let undeclared = SensorSweep::from_readings(&[], 0);
        assert!(!undeclared.is_complete());
    }
}
