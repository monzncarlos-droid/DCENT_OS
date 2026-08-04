//! Rank-31 (2026-08-03): integration pins for the VNish 1.2.7
//! thermal/hardware matrix (77 models) and its cross-corpus adjudication
//! against the ePIC jig registry and the live-measured `Hashboard` catalog.
//!
//! Proves, against the checked-in generated data:
//! 1. corpus shape (77 models, access/sensor-count/chain censuses, the
//!    3×216 and 4-chain extremes the schema was sized for),
//! 2. provenance is the distinct VNish third-party-transcription variant on
//!    every row — never ePIC, never live,
//! 3. corroborations: chips/domain topology agrees with the ePIC registry
//!    on all 36 overlapping SKUs and with the live catalog where they meet,
//! 4. conflicts are RECORDED, not resolved: the 14-SKU chains 3-vs-4
//!    disagreement, the A3HB70701 mux contradiction, the mux-bank
//!    under-report, and the 2-vs-4 sensor-roster divergence all pin BOTH
//!    sides verbatim,
//! 5. oddities are preserved verbatim (BHB68709 duplicate address, 0x98
//!    pseudo-addresses, non-universal chip_temp_offset).

use std::collections::BTreeMap;

use dcentrald_silicon_profiles::hashboard_topology::{descriptor_by_sku, DescriptorProvenance};
use dcentrald_silicon_profiles::hashboards::ALL_HASHBOARDS;
use dcentrald_silicon_profiles::vnish_thermal::{
    all_vnish_models, validate_vnish_descriptor, vnish_model_by_btm, VnishCoolingMode,
    VnishSensorAccess, VnishSensorLocation,
};

// ---------------------------------------------------------------------------
// 1. Corpus shape
// ---------------------------------------------------------------------------

#[test]
fn corpus_has_77_models_and_every_row_validates() {
    assert_eq!(all_vnish_models().len(), 77);
    let mut seen = std::collections::HashSet::new();
    for d in all_vnish_models() {
        assert!(seen.insert(d.btm_model.as_str()), "dup {}", d.btm_model);
        validate_vnish_descriptor(d).expect("row validates");
        let resolved = vnish_model_by_btm(&d.btm_model).expect("resolves");
        assert_eq!(resolved, d);
        // Every model row was observed in all four control-board platforms.
        assert_eq!(d.observed_platforms, ["aml", "bb", "cv", "xil"]);
    }
}

#[test]
fn access_and_sensor_count_censuses_match_the_source_matrix() {
    let mut access: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut counts: BTreeMap<u16, usize> = BTreeMap::new();
    for d in all_vnish_models() {
        let key = match d.sensor_access {
            VnishSensorAccess::Direct => "direct",
            VnishSensorAccess::ViaPic => "via_pic",
            VnishSensorAccess::ViaChipAuto => "via_chip_auto",
            VnishSensorAccess::ViaBusSwitch => "via_bus_switch",
        };
        *access.entry(key).or_default() += 1;
        *counts.entry(d.expected_sensors_per_board()).or_default() += 1;
    }
    // Per-model access census from the 2026-04-25 matrix.
    assert_eq!(access["direct"], 30);
    assert_eq!(access["via_pic"], 29);
    assert_eq!(access["via_bus_switch"], 16);
    assert_eq!(access["via_chip_auto"], 2);
    // Sensor counts range 2..=8 — including the 7- and 8-sensor hydro rows.
    assert_eq!(counts[&2], 31);
    assert_eq!(counts[&4], 39);
    assert_eq!(counts[&7], 4);
    assert_eq!(counts[&8], 3);
}

#[test]
fn schema_accommodates_the_corpus_extremes() {
    // 3×216 (S21 Hydro, 648 chips/unit) — the range the queue called out.
    let d = vnish_model_by_btm("HHB68501").expect("S21 Hydro");
    assert_eq!(d.chips_per_chain, 216);
    assert_eq!(d.chains_per_unit, 3);
    assert_eq!(d.declared_chips_per_unit(), 648);
    assert_eq!(
        all_vnish_models()
            .iter()
            .map(|d| d.chips_per_chain)
            .max()
            .unwrap(),
        216
    );
    // The six 4-chain hydro rows (largest per-unit population 4×180 = 720).
    let four_chain: Vec<&str> = all_vnish_models()
        .iter()
        .filter(|d| d.chains_per_unit == 4)
        .map(|d| d.btm_model.as_str())
        .collect();
    assert_eq!(
        four_chain,
        ["BHBXXXXX", "HHB28601", "HHB28602", "HHB42602", "HHB42631", "HHBXXX"]
    );
    assert_eq!(
        all_vnish_models()
            .iter()
            .map(|d| d.declared_chips_per_unit())
            .max()
            .unwrap(),
        720
    );
    // via-bus-switch topology is expressible and flagged as mux-gated.
    let d = vnish_model_by_btm("A3HB70501").expect("S21 XP");
    assert!(d.sensor_access.requires_bus_switch());
}

#[test]
fn immersion_only_census_is_25_and_blocks_are_honestly_absent() {
    let imm: Vec<&str> = all_vnish_models()
        .iter()
        .filter(|d| d.is_immersion_only())
        .map(|d| d.btm_model.as_str())
        .collect();
    assert_eq!(
        imm,
        [
            "BHBXXXXX",
            "H1HB68601",
            "H1HB70602",
            "H6HB56702",
            "H6HB70501",
            "H6HB70701",
            "H6HB70702",
            "H6HB70704",
            "H6HB70801",
            "H6HB70802",
            "HHB28601",
            "HHB28602",
            "HHB42602",
            "HHB42631",
            "HHB56601",
            "HHB56702",
            "HHB68501",
            "HHB68502",
            "HHB68503",
            "HHB68601",
            "HHB68701",
            "HHBXXX",
            "IHB68601",
            "M1HB70601",
            "M1HB70602"
        ]
    );
    for d in all_vnish_models() {
        if d.is_immersion_only() {
            // No auto/manual fan curve exists — and none was fabricated.
            assert_eq!(d.auto_target_c, None, "{}", d.btm_model);
            assert_eq!(d.manual_fan_pct, None, "{}", d.btm_model);
        } else {
            // Air-cooled rows declare all three modes + both blocks.
            assert_eq!(
                d.cooling_modes,
                [
                    VnishCoolingMode::Auto,
                    VnishCoolingMode::Manual,
                    VnishCoolingMode::Immersion
                ],
                "{}",
                d.btm_model
            );
            assert!(d.auto_target_c.is_some() && d.manual_fan_pct.is_some());
        }
    }
    // fan_min_count is independently absent on exactly 15 rows — all
    // immersion-only, but 10 immersion-only rows DO carry it.
    let missing_fmc = all_vnish_models()
        .iter()
        .filter(|d| d.fan_min_count.is_none())
        .count();
    assert_eq!(missing_fmc, 15);
    for d in all_vnish_models()
        .iter()
        .filter(|d| d.fan_min_count.is_none())
    {
        assert!(d.is_immersion_only(), "{}", d.btm_model);
    }
}

// ---------------------------------------------------------------------------
// 2. Provenance is the distinct third-party-transcription variant
// ---------------------------------------------------------------------------

#[test]
fn provenance_is_vnish_desk_on_every_row_and_distinct_from_the_other_corpora() {
    for d in all_vnish_models() {
        assert_eq!(
            d.provenance,
            DescriptorProvenance::DeskVnishFirmwareExperimental,
            "{}",
            d.btm_model
        );
        assert_ne!(d.provenance, DescriptorProvenance::DeskJigDbExperimental);
        assert_ne!(d.provenance, DescriptorProvenance::LiveMeasuredDcent);
    }
    // The ePIC registry keeps ITS provenance — the VNish import may not
    // relabel or absorb it.
    assert_eq!(
        descriptor_by_sku("BHB42601").unwrap().provenance,
        DescriptorProvenance::DeskJigDbExperimental
    );
}

// ---------------------------------------------------------------------------
// 3. Corroborations across independent transcriptions
// ---------------------------------------------------------------------------

#[test]
fn chip_and_domain_topology_agrees_with_the_epic_registry_on_all_36_overlaps() {
    let mut overlapping = 0;
    for d in all_vnish_models() {
        let Some(e) = descriptor_by_sku(&d.btm_model) else {
            continue;
        };
        overlapping += 1;
        assert_eq!(
            d.chips_per_chain, e.chain.chips_per_chain,
            "{}: chips/chain",
            d.btm_model
        );
        assert_eq!(
            d.chips_per_domain, e.chain.chips_per_domain,
            "{}: chips/domain",
            d.btm_model
        );
        assert_eq!(
            d.domains_per_chain, e.chain.domains_per_chain,
            "{}: domains/chain",
            d.btm_model
        );
    }
    // 36 of 77 VNish models overlap the 50-SKU ePIC roster; the other 41
    // (hydro/immersion, scrypt, S19a/S19i/T19-era, placeholder IDs) are new.
    assert_eq!(overlapping, 36);
    assert_eq!(
        all_vnish_models()
            .iter()
            .filter(|d| descriptor_by_sku(&d.btm_model).is_none())
            .count(),
        41
    );
}

#[test]
fn matrix_agrees_with_the_live_measured_catalog_where_they_meet() {
    // The live catalog remains the authority; the VNish matrix must not
    // silently disagree on the SKUs both know.
    let mut overlapping = 0;
    for hb in ALL_HASHBOARDS {
        let cat = hb.catalog();
        let Some(d) = vnish_model_by_btm(cat.sku) else {
            continue;
        };
        overlapping += 1;
        assert_eq!(
            d.chips_per_chain, cat.chips_per_chain as u16,
            "{}: VNish chips/chain vs live catalog",
            cat.sku
        );
    }
    // 12 of the 20 catalog SKUs appear in the VNish roster. Absent from
    // VNish: BHB42611/42632/42803/42811 and the legacy BHB-S9/S11/S17/T15
    // placeholders. Pinned to catch roster drift on either side.
    assert_eq!(overlapping, 12);
}

// ---------------------------------------------------------------------------
// 4. Conflicts: recorded verbatim on both sides, never resolved by edit
// ---------------------------------------------------------------------------

#[test]
fn chains_conflict_with_the_epic_registry_is_pinned_on_exactly_14_skus() {
    // VNish declares 3 hashboards where the ePIC jig DB declares 4 — and
    // VNish agrees with DCENT live evidence (3 slots on .79/.109/.129).
    // BOTH sides stay verbatim; this pin catches any silent "fix".
    let mut conflicts: Vec<&str> = Vec::new();
    for d in all_vnish_models() {
        let Some(e) = descriptor_by_sku(&d.btm_model) else {
            continue;
        };
        if u8::from(d.chains_per_unit) != e.chain.chains_per_unit {
            assert_eq!(d.chains_per_unit, 3, "{}: VNish side", d.btm_model);
            assert_eq!(e.chain.chains_per_unit, 4, "{}: ePIC side", d.btm_model);
            conflicts.push(d.btm_model.as_str());
        }
    }
    assert_eq!(
        conflicts,
        [
            "BHB42601", "BHB42603", "BHB42612", "BHB42621", "BHB42631", "BHB42641", "BHB42651",
            "BHB42701", "BHB42801", "BHB42821", "BHB42831", "BHB42841", "NBP1901", "NBS1902"
        ],
        "chains 3-vs-4 conflict set drifted — re-adjudicate, do not overwrite"
    );
}

#[test]
fn a3hb70701_sensor_topology_contradiction_is_pinned_not_resolved() {
    // VNish: 4 sensors via-bus-switch, all 0x4C. ePIC: 4 DIRECT sensors at
    // 0x48..=0x4B and NO switch bank. Unresolvable at the desk — a live
    // probe of an S21+ (A3HB70701) board is the only adjudicator.
    let v = vnish_model_by_btm("A3HB70701").unwrap();
    assert_eq!(v.sensor_access, VnishSensorAccess::ViaBusSwitch);
    assert_eq!(v.sensors.len(), 4);
    assert!(v.sensors.iter().all(|s| s.i2c_addr == 0x4C));

    let e = descriptor_by_sku("A3HB70701").unwrap();
    assert!(e.switch_sensors.is_empty(), "ePIC declares NO switch bank");
    assert_eq!(e.board_sensors.len(), 4);
    assert!(e
        .board_sensors
        .iter()
        .all(|s| (0x48..=0x4B).contains(&s.i2c_addr)));
}

#[test]
fn mux_bank_agreement_and_under_report_on_the_six_shared_a3hb_skus() {
    // On A3HB70501-503 / A3HB70601-603 both corpora agree a 4×0x4C mux bank
    // exists — but VNish lists ONLY that bank while ePIC also declares the
    // 4-sensor direct bank. Recorded as an under-report, not adjudicated.
    for sku in [
        "A3HB70501",
        "A3HB70502",
        "A3HB70503",
        "A3HB70601",
        "A3HB70602",
        "A3HB70603",
    ] {
        let v = vnish_model_by_btm(sku).unwrap();
        assert_eq!(v.sensor_access, VnishSensorAccess::ViaBusSwitch, "{sku}");
        assert_eq!(v.sensors.len(), 4, "{sku}");
        assert!(v.sensors.iter().all(|s| s.i2c_addr == 0x4C), "{sku}");

        let e = descriptor_by_sku(sku).unwrap();
        assert_eq!(e.switch_sensors.len(), 4, "{sku}");
        assert!(e.switch_sensors.iter().all(|s| s.i2c_addr == 0x4C), "{sku}");
        // The divergence: ePIC's additional direct bank.
        assert_eq!(e.board_sensors.len(), 4, "{sku}");
    }
}

#[test]
fn two_sensor_direct_rows_diverge_from_the_epic_four_sensor_board_bank() {
    // Modern boards: VNish reads a direct 0x48+0x4C pair where the ePIC DB
    // wires a 4-sensor 0x48..=0x4B board bank (plus a 0x48/0x4C ctrl pair).
    // Different models of different things — recorded, not merged. Count
    // the overlapping SKUs where the rosters disagree in size.
    let mut divergent = 0;
    for d in all_vnish_models() {
        let Some(e) = descriptor_by_sku(&d.btm_model) else {
            continue;
        };
        let epic_board_bank = e.board_sensors.len() + e.switch_sensors.len();
        if d.sensors.len() != epic_board_bank {
            divergent += 1;
            assert!(
                d.sensors.len() < epic_board_bank,
                "{}: VNish roster larger than ePIC's — new conflict class, re-adjudicate",
                d.btm_model
            );
        }
    }
    // 6 mux-only under-reports (4 vs 8) + 17 two-sensor rows (2 vs 4,
    // including A3HB70702/70703) = 23. A3HB70701 is NOT here — its rosters
    // are equal-sized but contradictory in kind (see its dedicated pin).
    assert_eq!(divergent, 23);
}

// ---------------------------------------------------------------------------
// 5. Oddities preserved verbatim
// ---------------------------------------------------------------------------

#[test]
fn chip_temp_offset_is_not_universal_15() {
    // The matrix doc's prose says "universal 15"; its own CSV disagrees.
    // The CSV is the import authority. Census: 15→63, 0→6, 10→5, 5→3.
    let mut census: BTreeMap<i16, usize> = BTreeMap::new();
    for d in all_vnish_models() {
        *census.entry(d.limits.chip_temp_offset_c).or_default() += 1;
    }
    assert_eq!(census[&15], 63);
    assert_eq!(census[&0], 6);
    assert_eq!(census[&10], 5);
    assert_eq!(census[&5], 3);
    // The offset-0 set includes the via-chip-auto S19a boards (ASIC-internal
    // sensing needs no board-to-junction offset) — pinned examples.
    assert_eq!(
        vnish_model_by_btm("BHB28611")
            .unwrap()
            .limits
            .chip_temp_offset_c,
        0
    );
    assert_eq!(
        vnish_model_by_btm("NBS1902")
            .unwrap()
            .limits
            .chip_temp_offset_c,
        10
    );
}

#[test]
fn shared_thresholds_hold_corpus_wide_but_min_start_splits() {
    for d in all_vnish_models() {
        assert_eq!(d.limits.danger_chip_c, 90, "{}", d.btm_model);
        assert_eq!(d.limits.hot_chip_c, 85, "{}", d.btm_model);
        assert_eq!(d.limits.danger_board_c, 80, "{}", d.btm_model);
        assert_eq!(d.limits.normal_start_c, 40, "{}", d.btm_model);
        assert!(
            d.limits.min_start_c == -30 || d.limits.min_start_c == 0,
            "{}",
            d.btm_model
        );
    }
    let cold_start = all_vnish_models()
        .iter()
        .filter(|d| d.limits.min_start_c == -30)
        .count();
    assert_eq!(cold_start, 62); // the other 15 declare 0
}

#[test]
fn bhb68709_duplicate_direct_address_is_preserved_verbatim() {
    // Two "direct" sensors at the SAME 0x4C address — physically ambiguous
    // as flat wiring; imported verbatim as a transcription oddity.
    let d = vnish_model_by_btm("BHB68709").unwrap();
    assert_eq!(d.sensor_access, VnishSensorAccess::Direct);
    let addrs: Vec<u8> = d.sensors.iter().map(|s| s.i2c_addr).collect();
    assert_eq!(addrs, [0x4C, 0x4C]);
}

#[test]
fn passthrough_pseudo_addresses_appear_only_on_pic_or_chip_auto_rows() {
    for d in all_vnish_models() {
        let has_0x98 = d.sensors.iter().any(|s| s.i2c_addr == 0x98);
        if has_0x98 {
            assert!(
                matches!(
                    d.sensor_access,
                    VnishSensorAccess::ViaPic | VnishSensorAccess::ViaChipAuto
                ),
                "{}: 0x98 pseudo-address on unexpected access route",
                d.btm_model
            );
        }
        // Mux rows are pure 0x4C — with ONE pinned exception: H6HB70802
        // (S21e Hydro) declares six 0x4C plus a trailing 0x48 on its
        // via-bus-switch roster. Imported verbatim; if the exception set
        // grows or shrinks, re-adjudicate.
        match d.sensor_access {
            VnishSensorAccess::ViaBusSwitch => {
                if d.btm_model == "H6HB70802" {
                    let addrs: Vec<u8> = d.sensors.iter().map(|s| s.i2c_addr).collect();
                    assert_eq!(addrs, [0x4C, 0x4C, 0x4C, 0x4C, 0x4C, 0x4C, 0x48]);
                } else {
                    assert!(
                        d.sensors.iter().all(|s| s.i2c_addr == 0x4C),
                        "{}",
                        d.btm_model
                    );
                }
            }
            VnishSensorAccess::Direct => {
                assert!(
                    d.sensors.iter().all(|s| s.is_seven_bit_addr()),
                    "{}",
                    d.btm_model
                );
            }
            _ => {}
        }
    }
}

#[test]
fn middle_location_exists_only_on_the_eight_sensor_hydro_rows() {
    let with_middle: Vec<&str> = all_vnish_models()
        .iter()
        .filter(|d| d.sensors_at(VnishSensorLocation::Middle).next().is_some())
        .map(|d| d.btm_model.as_str())
        .collect();
    assert_eq!(with_middle, ["HHB28601", "HHB28602"]);
    for m in with_middle {
        let d = vnish_model_by_btm(m).unwrap();
        assert_eq!(d.expected_sensors_per_board(), 8);
        assert_eq!(d.chains_per_unit, 4);
        assert!(d.is_immersion_only());
        assert_eq!(d.sensors_at(VnishSensorLocation::Middle).count(), 3);
    }
}

#[test]
fn rev_variant_and_placeholder_designators_are_verbatim_registry_keys() {
    // Trailing-dash rev variants are distinct models in VNish — both
    // spellings must resolve independently.
    for (a, b) in [
        ("BHB56804-", "BHB56804"),
        ("BHB56902-", "BHB56902"),
        ("BHB56903-", "BHB56903"),
        ("BHB68603-", "BHB68603"),
        ("BHB68701-", "BHB68701"),
    ] {
        let da = vnish_model_by_btm(a).expect(a);
        let db = vnish_model_by_btm(b).expect(b);
        assert_ne!(da.btm_model, db.btm_model);
    }
    // Placeholder designators ship in VNish exactly like this.
    for m in ["42801", "BHBXXXX", "BHBXXXXX", "HHBXXX"] {
        assert!(vnish_model_by_btm(m).is_some(), "{m}");
    }
}
