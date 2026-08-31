//! Daemon wiring contract for gauntlet #11 bad-chip decrease-only actuation.
//!
//! Pins the production `daemon.rs` caller, not a re-implementation. Needles
//! are literals of the production lines so deleting the wiring fails this file
//! (and cannot be satisfied by this test's own source).

const DAEMON_SRC: &str = include_str!("../src/daemon.rs");

#[test]
fn daemon_plans_bad_chip_actions_through_shipped_policy() {
    assert!(
        DAEMON_SRC.contains("dcentrald_autotuner::plan_bad_chip_actuation_on_chain("),
        "daemon.rs must plan BadChipAction through the shipped actuation policy"
    );
    assert!(
        DAEMON_SRC.contains("dcentrald_autotuner::resolve_health_operating_mhz("),
        "daemon.rs must resolve expected-nonce MHz from live operating freq"
    );
    assert!(
        DAEMON_SRC.contains("dcentrald_autotuner::bad_chip_actuation_armed("),
        "daemon.rs must keep actuation behind the enabled+actuate gate"
    );
    assert!(
        DAEMON_SRC.contains("apply_bad_chip_actuation(&bad_chip_freq_tx, &planned);"),
        "daemon.rs must apply planned decrease-only intents on the freq channel"
    );
    assert!(
        DAEMON_SRC.contains("dcentrald_autotuner::actuation_bases("),
        "daemon.rs must not recompute ReduceBoardProfile from live nameplate"
    );
    assert!(
        DAEMON_SRC.contains("supervisor.invalidate_after_downclock("),
        "daemon.rs must invalidate the health window after a downclock"
    );
    let compact_daemon: String = DAEMON_SRC.split_whitespace().collect();
    assert!(
        compact_daemon.contains("self.config.autotuner.enabled||bad_chip_enabled"),
        "health snapshots must not require frequency autotune"
    );
    assert!(
        compact_daemon.contains(
            "letspawn_autotuner=self.config.autotuner.enabled&&!(am2_bm1362_family&&!am2_freq_autotune_opted_in);"
        ),
        "AM2 default must keep TABS gated even when the health tee is on"
    );
}

#[test]
fn daemon_actuation_is_decrease_only_badchip_source() {
    assert!(
        DAEMON_SRC.contains("source: dcentrald_autotuner::FrequencyLimitSource::BadChip,"),
        "actuation must use the dedicated BadChip ceiling slot"
    );
    assert!(
        DAEMON_SRC.contains("FreqCommand::SetChipFrequencyLimit"),
        "per-chip downclock/blacklist must be a chip ceiling, not SetVoltage"
    );
    assert!(
        !DAEMON_SRC.contains("apply_bad_chip_actuation")
            || !DAEMON_SRC[DAEMON_SRC.find("fn apply_bad_chip_actuation").unwrap_or(0)
                ..DAEMON_SRC.find("fn apply_bad_chip_actuation").unwrap_or(0) + 1800]
                .contains("SetVoltage"),
        "apply_bad_chip_actuation must not send SetVoltage"
    );
}

#[test]
fn daemon_does_not_actuate_board_reset() {
    let start = DAEMON_SRC
        .find("fn apply_bad_chip_actuation")
        .expect("apply_bad_chip_actuation must exist");
    let body = &DAEMON_SRC[start..start + 1800];
    assert!(
        body.contains("BadChipActuation::Refuse"),
        "apply helper must ignore Refuse (BoardReset / out-of-range)"
    );
    assert!(
        !body.contains("BoardReset"),
        "apply helper must not implement BoardReset itself"
    );
}
