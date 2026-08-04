//! Rank-33 (2026-08-03): integration pins for the declarative sensor
//! topology and the shared coverage type.
//!
//! Proves, against the checked-in v1.22.0 registry data:
//! 1. every one of the 50 SKUs yields a sensor set with the corpus shape,
//! 2. the 36 I²C-mux (`switchsensor`) entries round-trip losslessly,
//! 3. the shared `SensorSweep`/`SweepLedger` type expresses all three
//!    existing bespoke coverage shapes (`AmlogicTemperatureCoverage`,
//!    `Am3BbThermalSnapshot`, ESP `MuxedDieFold`) — mapping-only; the call
//!    sites themselves are deliberately untouched in this pass,
//! 4. unknown-vs-zero: a missing reading is never 0 °C and never satisfies
//!    a safety check.

use dcentrald_silicon_profiles::hashboard_topology::{
    all_descriptors, descriptor_by_sku, DescriptorProvenance,
};
use dcentrald_silicon_profiles::sensor_topology::{
    all_sensor_topologies, sensor_topology_for_sku, try_build_sensor_topology, BoardEdgeX,
    BoardEdgeY, GroupRequirement, SensorSite, SensorSpec, SensorSweep, SensorTransport, SweepGroup,
    SweepLedger,
};

// ---------------------------------------------------------------------------
// 1. Every SKU yields a sensor set with the pinned corpus shape
// ---------------------------------------------------------------------------

#[test]
fn all_fifty_skus_yield_a_sensor_set() {
    assert_eq!(all_sensor_topologies().len(), 50);
    for d in all_descriptors() {
        let t = sensor_topology_for_sku(&d.sku).expect("every registry SKU resolves");
        // Fail-closed builder agrees with the cached registry.
        let rebuilt = try_build_sensor_topology(d).expect("pinned corpus builds");
        assert_eq!(&rebuilt, t, "{}", d.sku);
        // Direct hashboard bank: exactly 4 on every board, 0x48..=0x4B.
        assert_eq!(t.expected_direct_per_hashboard(), 4, "{}", d.sku);
        // Sensor identity is LM75A throughout the corpus.
        for s in &t.sensors {
            assert_eq!(s.device, "LM75A", "{}", d.sku);
            assert!(
                (0x48..=0x4C).contains(&s.transport.i2c_addr()),
                "{}: addr {:#x}",
                d.sku,
                s.transport.i2c_addr()
            );
        }
    }
}

#[test]
fn corpus_totals_match_the_evidence_db_including_the_mux_bank() {
    let mut direct_board = 0u32;
    let mut ctrl = 0u32;
    let mut muxed = 0u32;
    for t in all_sensor_topologies() {
        direct_board += u32::from(t.expected_direct_per_hashboard());
        ctrl += u32::from(t.expected_ctrl_board());
        muxed += u32::from(t.expected_muxed_per_hashboard());
    }
    // The widely-quoted "266 LM75A instances" counts only the direct banks;
    // the switchsensor mux bank raises the true declared total to 302.
    assert_eq!(direct_board, 200);
    assert_eq!(ctrl, 66);
    assert_eq!(direct_board + ctrl, 266);
    assert_eq!(muxed, 36);
    assert_eq!(direct_board + ctrl + muxed, 302);
    // Ctrl-board pair (0x48 right/top + 0x4C left/top) on exactly 33 rows.
    let with_ctrl = all_sensor_topologies()
        .iter()
        .filter(|t| t.expected_ctrl_board() > 0)
        .count();
    assert_eq!(with_ctrl, 33);
    for t in all_sensor_topologies() {
        let n = t.expected_ctrl_board();
        assert!(n == 0 || n == 2, "{}: ctrl bank is a pair or absent", t.sku);
    }
}

// ---------------------------------------------------------------------------
// 2. Muxed entries round-trip
// ---------------------------------------------------------------------------

const MUX_SKUS: [&str; 9] = [
    "A3HB70501",
    "A3HB70502",
    "A3HB70503",
    "A3HB70601",
    "A3HB70602",
    "A3HB70603",
    "A3HB70605",
    "A3HB70606",
    "A3HB70607",
];

#[test]
fn mux_bank_exists_on_exactly_the_nine_a3hb_boards() {
    for t in all_sensor_topologies() {
        let expected = if MUX_SKUS.contains(&t.sku.as_str()) {
            4
        } else {
            0
        };
        assert_eq!(
            t.expected_muxed_per_hashboard(),
            expected,
            "{}: mux bank presence drifted — re-adjudicate against the DB",
            t.sku
        );
    }
}

#[test]
fn muxed_entries_round_trip_through_descriptor_and_serde() {
    for sku in MUX_SKUS {
        let d = descriptor_by_sku(sku).expect("registry row");
        let t = sensor_topology_for_sku(sku).expect("sensor set");
        // Descriptor -> spec is lossless for every switch-sensor field.
        let muxed: Vec<&SensorSpec> = t.muxed_sensors().collect();
        assert_eq!(muxed.len(), d.switch_sensors.len(), "{sku}");
        for (raw, spec) in d.switch_sensors.iter().zip(&muxed) {
            assert_eq!(spec.site, SensorSite::Hashboard, "{sku}");
            assert_eq!(spec.index, raw.index, "{sku}");
            match spec.transport {
                SensorTransport::I2cMuxed {
                    i2c_addr,
                    anchor_asic,
                    power_by_ctrlboard,
                } => {
                    assert_eq!(i2c_addr, raw.i2c_addr, "{sku}");
                    assert_eq!(i2c_addr, 0x4C, "{sku}");
                    assert_eq!(anchor_asic, raw.anchor_asic, "{sku}");
                    assert_eq!(power_by_ctrlboard, raw.power_by_ctrlboard, "{sku}");
                }
                SensorTransport::DirectI2c { .. } => panic!("{sku}: mux spec lost its transport"),
            }
        }
        // Serde round-trip of both layers.
        let json = serde_json::to_string(&d.switch_sensors).expect("serialize placements");
        let back: Vec<dcentrald_silicon_profiles::hashboard_topology::SwitchSensorPlacement> =
            serde_json::from_str(&json).expect("deserialize placements");
        assert_eq!(back, d.switch_sensors, "{sku}");
        let json = serde_json::to_string(t).expect("serialize topology");
        let back: dcentrald_silicon_profiles::sensor_topology::SkuSensorTopology =
            serde_json::from_str(&json).expect("deserialize topology");
        assert_eq!(&back, t, "{sku}");
    }
}

#[test]
fn mux_anchor_chips_are_pinned_per_family() {
    // A3HB705xx (91-chip boards) anchor at chips {1, 7, 43, 68};
    // A3HB706xx (65-chip boards) anchor at chips {5, 18, 40, 48}.
    for sku in ["A3HB70501", "A3HB70502", "A3HB70503"] {
        let t = sensor_topology_for_sku(sku).unwrap();
        let mut anchors: Vec<u16> = t
            .muxed_sensors()
            .map(|s| match s.transport {
                SensorTransport::I2cMuxed { anchor_asic, .. } => anchor_asic,
                _ => unreachable!(),
            })
            .collect();
        anchors.sort_unstable();
        assert_eq!(anchors, vec![1, 7, 43, 68], "{sku}");
    }
    for sku in [
        "A3HB70601",
        "A3HB70602",
        "A3HB70603",
        "A3HB70605",
        "A3HB70606",
        "A3HB70607",
    ] {
        let t = sensor_topology_for_sku(sku).unwrap();
        let mut anchors: Vec<u16> = t
            .muxed_sensors()
            .map(|s| match s.transport {
                SensorTransport::I2cMuxed { anchor_asic, .. } => anchor_asic,
                _ => unreachable!(),
            })
            .collect();
        anchors.sort_unstable();
        assert_eq!(anchors, vec![5, 18, 40, 48], "{sku}");
    }
}

/// Transcription defect pin (same posture as the BHB42803 transposition pin):
/// A3HB70601 omits `power_by_ctrlboard` on all four mux entries AND orders
/// its `index`→`anchor_asic` mapping differently from its six A3HB706xx
/// siblings. Imported verbatim; if either side ever changes, re-adjudicate
/// against the evidence DB instead of silently "fixing" one side.
#[test]
fn a3hb70601_transcription_defect_is_pinned_not_reconciled() {
    let outlier = descriptor_by_sku("A3HB70601").unwrap();
    for s in &outlier.switch_sensors {
        assert_eq!(
            s.power_by_ctrlboard, None,
            "A3HB70601 mux entries carry no power_by_ctrlboard in the DB"
        );
    }
    let by_index = |sku: &str| -> Vec<(u8, u16)> {
        let d = descriptor_by_sku(sku).unwrap();
        let mut v: Vec<(u8, u16)> = d
            .switch_sensors
            .iter()
            .map(|s| (s.index, s.anchor_asic))
            .collect();
        v.sort_unstable();
        v
    };
    // Outlier: index 0 -> chip 5; siblings: index 0 -> chip 18.
    assert_eq!(
        by_index("A3HB70601"),
        vec![(0, 5), (1, 18), (2, 48), (3, 40)]
    );
    for sibling in [
        "A3HB70602",
        "A3HB70603",
        "A3HB70605",
        "A3HB70606",
        "A3HB70607",
    ] {
        assert_eq!(
            by_index(sibling),
            vec![(0, 18), (1, 5), (2, 48), (3, 40)],
            "{sibling}"
        );
        for s in &descriptor_by_sku(sibling).unwrap().switch_sensors {
            assert!(
                s.power_by_ctrlboard.is_some(),
                "{sibling}: siblings DO carry power_by_ctrlboard"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 3. The shared coverage type expresses all three bespoke shapes
// ---------------------------------------------------------------------------

/// Mapping proof #1 — ESP `MuxedDieFold` (dcentos-esp thermal_safety.rs):
/// `SensorSweep` IS the same shape: {hottest, covered, expected} with
/// finite-only counting and `covered == expected` completeness. Replays the
/// exact upstream fail-open scenario the ESP type exists to refuse.
#[test]
fn sweep_expresses_muxed_die_fold() {
    // NerdOCTAXE-γ shape: 8 dies, one live at 45 C, seven failed.
    let readings: Vec<Option<f32>> = std::iter::once(Some(45.0))
        .chain(std::iter::repeat(None).take(7))
        .collect();
    let sweep = SensorSweep::from_readings(&readings, 8);
    // Upstream folded this to a healthy "45.0"; the shared type keeps the
    // hot measured die visible AND reports the sweep as incomplete.
    assert_eq!(sweep.hottest_c, Some(45.0));
    assert_eq!(sweep.covered, 1);
    assert_eq!(sweep.expected, 8);
    assert!(!sweep.is_complete());

    // MuxedDieFold::is_complete: expected > 0 && covered == expected.
    assert!(SensorSweep::from_readings(&[Some(1.0); 8], 8).is_complete());
    assert!(!SensorSweep::from_readings(&[], 0).is_complete()); // 0 never complete
    assert!(!SensorSweep::from_readings(&[Some(1.0); 9], 8).is_complete()); // over-coverage

    // NaN channels are failures, never coverage (the upstream bug's root).
    let nan_sweep = SensorSweep::from_readings(&[Some(f32::NAN); 4], 4);
    assert_eq!(nan_sweep.covered, 0);
    assert_eq!(nan_sweep.hottest_c, None);
}

/// Mapping proof #2 — `AmlogicTemperatureCoverage` (dcentrald-hal amlogic):
/// per required slot, inlet AND outlet must be available. Ledger encoding:
/// one `Exact`-required group per required slot×position. Verified against a
/// truth table replaying their `is_complete`/`missing_slots` semantics.
#[test]
fn ledger_expresses_amlogic_temperature_coverage() {
    // (required_slots, inlet_available, outlet_available) scenarios.
    let scenarios: &[([bool; 3], [bool; 3], [bool; 3], bool, Vec<u8>)] = &[
        // All three slots required and fully covered.
        (
            [true, true, true],
            [true, true, true],
            [true, true, true],
            true,
            vec![],
        ),
        // Slot 1 missing its outlet: incomplete, missing slot 1.
        (
            [true, true, true],
            [true, true, true],
            [true, false, true],
            false,
            vec![1],
        ),
        // Unpopulated slot 2 requires nothing (their `!required` arm).
        (
            [true, true, false],
            [true, true, false],
            [true, true, false],
            true,
            vec![],
        ),
        // A reading on a NON-required slot must not mask a required gap.
        (
            [true, false, false],
            [false, true, true],
            [false, true, true],
            false,
            vec![0],
        ),
    ];
    for (required, inlet, outlet, want_complete, want_missing) in scenarios {
        let mut ledger = SweepLedger::default();
        for slot in 0..3usize {
            if !required[slot] {
                continue;
            }
            let inlet_reading = if inlet[slot] { Some(40.0) } else { None };
            let outlet_reading = if outlet[slot] { Some(50.0) } else { None };
            ledger.push(SweepGroup::exact(
                format!("slot{slot}/inlet"),
                SensorSweep::from_readings(&[inlet_reading], 1),
            ));
            ledger.push(SweepGroup::exact(
                format!("slot{slot}/outlet"),
                SensorSweep::from_readings(&[outlet_reading], 1),
            ));
        }
        assert_eq!(ledger.is_complete(), *want_complete);
        // missing_labels ≙ missing_slots (their per-slot fold, our labels).
        let missing_slots: Vec<u8> = ledger
            .missing_labels()
            .iter()
            .map(|l| l.as_bytes()[4] - b'0')
            .fold(Vec::new(), |mut acc, s| {
                if !acc.contains(&s) {
                    acc.push(s);
                }
                acc
            });
        assert_eq!(&missing_slots, want_missing);
    }
}

/// Mapping proof #3 — `Am3BbThermalSnapshot` (dcentrald am3_bb_mining.rs):
/// per-chain sample counting with a minimum-samples threshold
/// (`AM3_BB_THERMAL_MIN_SAMPLES_PER_CHAIN = 1`) and
/// `fresh = expected_chains > 0 && covered_chains == expected_chains
///        && max_temp_c.is_finite()`. Ledger encoding: one `AtLeast(min)`
/// group per expected chain; `is_fresh` reproduces their rule.
#[test]
fn ledger_expresses_am3_bb_thermal_snapshot() {
    const MIN_SAMPLES: u16 = 1; // AM3_BB_THERMAL_MIN_SAMPLES_PER_CHAIN
    let build = |samples_per_chain: &[&[Option<f32>]]| -> SweepLedger {
        let mut ledger = SweepLedger::default();
        for (chain, readings) in samples_per_chain.iter().enumerate() {
            // The dsPIC LM75 bridge yields a variable sample count; the
            // topology declares 4 board sensors per chain corpus-wide.
            ledger.push(SweepGroup::at_least(
                format!("chain{chain}"),
                SensorSweep::from_readings(readings, 4),
                MIN_SAMPLES,
            ));
        }
        ledger
    };

    // All three chains sampled -> fresh, max carried.
    let fresh = build(&[
        &[Some(60.0), Some(61.0)],
        &[Some(65.375)],
        &[Some(58.0), Some(59.0), Some(60.0)],
    ]);
    assert!(fresh.is_fresh());
    assert_eq!(fresh.hottest_c(), Some(65.375));
    assert_eq!(fresh.covered(), 6); // their `samples` total

    // A silent chain (their covered_chains < expected_chains) -> not fresh,
    // and the gap is NAMED rather than folded away.
    let silent = build(&[&[Some(60.0)], &[], &[Some(58.0)]]);
    assert!(!silent.is_fresh());
    assert_eq!(silent.missing_labels(), vec!["chain1"]);
    // A healthy peer's max must still be visible for logging...
    assert_eq!(silent.hottest_c(), Some(60.0));
    // ...but freshness (the only actuation gate) is refused.

    // No chains at all (their expected_chains == 0) -> never fresh.
    assert!(!build(&[]).is_fresh());

    // All bridges decode garbage (their max = NEG_INFINITY, not finite):
    // the shared type reports blind (None), which likewise fails freshness.
    let blind = build(&[&[Some(f32::NAN)], &[None]]);
    assert!(!blind.is_fresh());
    assert_eq!(blind.hottest_c(), None);
}

// ---------------------------------------------------------------------------
// 4. Unknown-vs-zero is pinned at the integration surface too
// ---------------------------------------------------------------------------

#[test]
fn absent_sensor_is_unknown_never_cool() {
    let t = sensor_topology_for_sku("A3HB70601").expect("registry row");
    // The declared per-hashboard expectation includes the mux bank:
    // 4 direct + 4 muxed.
    assert_eq!(t.expected_per_hashboard(), 8);
    // A reader that ignores the mux can at best cover the direct bank...
    let direct_only = SensorSweep::from_readings(&[Some(50.0); 4], t.expected_per_hashboard());
    assert_eq!(direct_only.covered, 4);
    // ...and MUST come out incomplete: the four muxed sensors are unknown,
    // not cool.
    assert!(!direct_only.is_complete());
    assert!(!direct_only.known_cooler_than(200.0));
    // The empty sweep is fully unknown: no reading, no 0.0 fabrication.
    let empty = t.empty_hashboard_sweep();
    assert_eq!(empty.hottest_c, None);
    assert_eq!(empty.covered, 0);
    assert_eq!(empty.expected, 8);
    assert!(!empty.known_cooler_than(f32::MAX));
}

#[test]
fn positions_support_gradient_queries() {
    // Direct board bank on BHB42601: verify position zones are queryable
    // (top vs bottom pairing is the gradient primitive).
    let t = sensor_topology_for_sku("BHB42601").expect("registry row");
    let top: Vec<&SensorSpec> = t
        .sensors_at(SensorSite::Hashboard, BoardEdgeX::Left, BoardEdgeY::Top)
        .chain(t.sensors_at(SensorSite::Hashboard, BoardEdgeX::Right, BoardEdgeY::Top))
        .collect();
    let bottom: Vec<&SensorSpec> = t
        .sensors_at(SensorSite::Hashboard, BoardEdgeX::Left, BoardEdgeY::Bottom)
        .chain(t.sensors_at(SensorSite::Hashboard, BoardEdgeX::Right, BoardEdgeY::Bottom))
        .collect();
    // Every declared hashboard sensor lands in exactly one zone.
    assert_eq!(
        top.len() + bottom.len(),
        t.expected_per_hashboard() as usize
    );
    // Provenance stays desk/Experimental on every returned spec.
    assert!(top
        .iter()
        .chain(&bottom)
        .all(|s| s.provenance == DescriptorProvenance::DeskJigDbExperimental));
}

#[test]
fn informational_groups_keep_unreachable_banks_visible() {
    // The S21-NoPic caveat in practice: on a platform where PIC-mediated
    // sensor access is NOT proven, the bank can be carried as Informational
    // — visible in the ledger, contributing readings if any, but never
    // silently counted as satisfied safety coverage by is_fresh alone.
    let mut ledger = SweepLedger::default();
    ledger.push(SweepGroup::informational(
        "hashboard-bank/unproven-access-path",
        SensorSweep::from_readings(&[None; 4], 4),
    ));
    assert_eq!(ledger.expected(), 4);
    assert_eq!(ledger.covered(), 0);
    assert!(!ledger.is_fresh(), "informational-only is never fresh");
    // Add the actually-proven gating source; freshness then follows it.
    ledger.push(SweepGroup::exact(
        "soc-die",
        SensorSweep::from_readings(&[Some(49.3)], 1),
    ));
    assert!(ledger.is_fresh());
    assert_eq!(ledger.hottest_c(), Some(49.3));
    // Requirement kinds are what they claim (no silent promotion).
    assert_eq!(
        ledger.groups[0].requirement,
        GroupRequirement::Informational
    );
    assert_eq!(ledger.groups[1].requirement, GroupRequirement::Exact);
}
