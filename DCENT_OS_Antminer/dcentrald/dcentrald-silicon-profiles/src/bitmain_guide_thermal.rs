//! Round-17 B3 (2026-08-08): first-party Bitmain maintenance-guide thermal
//! corpus — declarative sensor-topology facts as DATA.
//!
//! # What this is
//!
//! A third, independent desk corpus alongside [`crate::sensor_topology`]
//! (ePIC-transcribed jig DB, 50 SKUs) and [`crate::vnish_thermal`] (VNish
//! 1.2.7 model matrix, 77 rows): the **21 first-party Bitmain maintenance
//! guides** held at  (464
//! pages, extracted to `_text/*.txt` with `===== PAGE N =====` markers —
//! every fact in this module cites guide txt + PDF page).
//!
//! Unlike the other two corpora these documents are **Bitmain's own**, which
//! makes them the first first-party source for per-board expected sensor
//! counts. Where a guide states a count (S11 = 2, S15 = 4, S19 / S19 Pro /
//! S19+ = 4) it lands here as data; where it does not (S9 revision-ambiguous,
//! S19j Pro's TOC-promised temperature section is absent from its body,
//! S17+/T17e/L3+ never state one, S9k/S9SE facts are image-only), the field
//! is `None` and MUST stay `None` — a sensor count inferred from a sibling
//! board is not evidence for this board (test-pinned below).
//!
//! # What this is NOT
//!
//! - **Not runtime behaviour.** Nothing consumes these rows in a control
//!   path; no thermal trip, fan curve, or shutdown changes. Coverage
//!   accounting stays report-only per the Round-17 campaign rule (wiring a
//!   declared count into a shutdown path converts a blindness defect into an
//!   availability defect on a beta tier).
//! - **Not a part-identity authority for the S19 family.** No guide names
//!   the S19-family sensor IC. The jig DB's `"LM75A"` string remains
//!   protocol-compatibility evidence only (the dsPIC LM75 passthrough at
//!   0x48–0x4B is live-proven on `a lab unit`), while the guides' matching-resistor
//!   + TEMP_P/TEMP_N prose is remote-diode wiring evidence. Both are
//!   recorded; neither is promoted to a BOM fact.
//! - **Not typo-corrected.** Part strings and pin numbers are verbatim,
//!   including the guide's "ECT218" (almost certainly NCT218) and the T9+
//!   "pin 2 and pin 16" (contradicts the BM1387 pin map's 15/16 and the S9
//!   guide itself). Flags live in comments, not silent fixes.
//!
//! Full extraction + agreements/contradictions/refusals:
//! .

/// Provenance marker for every row in this module: a named first-party
/// Bitmain maintenance guide (txt basename in the extraction corpus) plus
/// the PDF page the sensor facts sit on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuideCitation {
    /// Basename under .
    pub guide_txt: &'static str,
    /// PDF page number (from the `===== PAGE N =====` extraction markers).
    pub page: u16,
}

/// One first-party thermal row. Every populated field is stated by the cited
/// guide; every absent field is a refusal, not an unknown-default.
#[derive(Debug, Clone, PartialEq)]
pub struct GuideThermalRow {
    /// Bitmain model name as the guide titles it.
    pub model: &'static str,
    /// ASIC family named in the guide's temperature-sensor section, verbatim
    /// (e.g. the S11 guide spells it "BM1387BF").
    pub asic: Option<&'static str>,
    /// Built-in temperature-diode pins as the guide states them, VERBATIM —
    /// T9+ says (2, 16) where the BM1387 pin map says (15, 16); preserved.
    pub asic_temp_pins: Option<(u8, u8)>,
    /// Pins through which the collected temperature returns toward the
    /// control-board FPGA (via RI), as stated.
    pub asic_return_pins: Option<(u8, u8)>,
    /// External temperature-sensor ICs per hashboard — ONLY where the guide
    /// states a count. `None` = the guide does not state one (never infer
    /// from a sibling model; test-pinned).
    pub board_sensor_count: Option<u8>,
    /// Sensor refdes positions where stated (e.g. S19: U4/U6/U7/U8).
    pub sensor_positions: &'static [&'static str],
    /// Verbatim part-candidate roster where stated (S9 only in this corpus).
    /// "ECT218" / "DRU1" / "411B" / "411C" are the guide's own spellings.
    pub sensor_part_candidates: &'static [&'static str],
    /// The guide describes remote-diode wiring between sensor and chip
    /// (TEMP_P/TEMP_N connection and/or per-sensor matching resistors).
    pub remote_diode_wiring: bool,
    /// Sensor supply rail where stated (S19 family: "3.3V").
    pub sensor_supply: Option<&'static str>,
    /// Normal operating temperature range (°C) where stated.
    pub normal_temp_range_c: Option<(i16, i16)>,
    /// Stock-firmware PCB-temperature alarm limit (°C) where stated
    /// ("cannot exceed 90 degrees … will alarm and fail to work normally").
    pub pcb_temp_alarm_c: Option<i16>,
    /// Whole-machine cooling-fan count where stated.
    pub fan_count: Option<u8>,
    /// PSU model named in the guide's machine-composition section.
    pub psu: Option<&'static str>,
    /// Primary citation for the sensor facts in this row.
    pub citation: GuideCitation,
    /// Free-text caveats (typo flags, intra-corpus variance, doc defects).
    pub notes: &'static str,
}

/// The corpus. Order: chronological product generations.
///
/// REFUSED (deliberately no row / no count — see the B3 deliverable §4):
/// S9k/S9SE (facts image-only), and per-field refusals inline below.
pub const GUIDE_THERMAL_ROWS: &[GuideThermalRow] = &[
    GuideThermalRow {
        model: "S9",
        asic: Some("BM1387"),
        // S9 guide p.12: "chip build-in temperature sensor group (BM1387 pin
        // 15 and pin 16) … return to FPGA of control panel from RI via
        // BM1387 pin 17 and pin 18".
        asic_temp_pins: Some((15, 16)),
        asic_return_pins: Some((17, 18)),
        // REFUSED: p.12 prose describes one external sensor circuit, p.22
        // says "hashboard of dual temperature sensor", Primary training p.46
        // says "U89, U102" — revision-dependent; no single count exists.
        board_sensor_count: None,
        // S9 guide p.22: TMP-class parts "usually in U89"; DRU1/411B/411C
        // "usually in U91". (Primary training p.46 says U89 + U102 — a
        // different board revision; recorded in notes.)
        sensor_positions: &["U89", "U91"],
        // Verbatim p.22. "ECT218" is almost certainly NCT218 (the in-tree
        // decoder treats ECT218 as unsourced); "411B"/"411C" are TMP411B/C
        // top-markings; "DRU1" is a package marking, not a part number.
        sensor_part_candidates: &[
            "TMP451", "TMP461", "TMP421", "TMP431", "ECT218", "DRU1", "411B", "411C",
        ],
        remote_diode_wiring: true,
        sensor_supply: None,
        // p.12: "The normal temperature range of the chip … is 65-125
        // degrees Celsius". The max-running-temperature NUMBER is absent in
        // the source PDF text itself (pymupdf-verified) — REFUSED.
        normal_temp_range_c: Some((65, 125)),
        pcb_temp_alarm_c: None,
        // p.24/28: two fans; one-fan-detected => protection halt.
        fan_count: Some(2),
        psu: None,
        citation: GuideCitation {
            guide_txt: "s9__S9_Maintenance_Guide.txt",
            page: 12,
        },
        notes: "V1.9 temp-sensor I2C bus wired to chips 62(U66)/46(U50)/25(U29)/2(U10) (p.12); \
                sensor IC beside chip 62 (p.22); dual-sensor boards exist (p.22); training \
                material p.46 names U89+U102 (revision variance); over-range => red light + \
                alarm + machine halts (p.12).",
    },
    GuideThermalRow {
        model: "T9+",
        asic: Some("BM1387"),
        // VERBATIM T9+ guide p.12: "(BM1387 pin 2 and pin 16)" — contradicts
        // the BM1387 pin map (TEMP_P/N = 15/16) and the S9 guide; preserved
        // as a first-party typo candidate. Do not propagate.
        asic_temp_pins: Some((2, 16)),
        asic_return_pins: Some((17, 18)),
        board_sensor_count: None, // not stated
        // p.13: "T9+ Temperature Sensor IC connects the first chip (U6) of
        // No. 2 signal chain".
        sensor_positions: &["U6"],
        sensor_part_candidates: &[],
        remote_diode_wiring: true,
        sensor_supply: None,
        normal_temp_range_c: None,
        pcb_temp_alarm_c: None,
        fan_count: Some(2), // FAN2 failure judgment (training p.18-19, "S9, T9+")
        psu: None,
        citation: GuideCitation {
            guide_txt: "s9__T9_Maintenance_Guide.txt",
            page: 12,
        },
        notes: "Sensor IC anchored to the first chip (U6) of signal chain 2 (p.13). 'pin 2' is \
                a typo candidate for pin 15.",
    },
    GuideThermalRow {
        model: "S11",
        asic: Some("BM1387BF"), // the S11 guide's own spelling (pin table)
        asic_temp_pins: Some((15, 16)),
        asic_return_pins: Some((17, 18)),
        // p.8: "two groups of temperature sensor, one is composed of
        // temperature sensor U5 and computing chip U39, and the other is
        // composed of U7 and computing chip U66" — a stated count of 2.
        board_sensor_count: Some(2),
        sensor_positions: &["U5", "U7"],
        sensor_part_candidates: &[],
        remote_diode_wiring: true,
        sensor_supply: None,
        normal_temp_range_c: None,
        pcb_temp_alarm_c: None,
        fan_count: Some(2), // dual fans; one-fan-detected => protection (p.12)
        psu: None,
        citation: GuideCitation {
            guide_txt: "misc__S11Maintenance_Guide.txt",
            page: 8,
        },
        notes: "Sensor groups anchored to computing chips U39 and U66 (p.8).",
    },
    GuideThermalRow {
        model: "S15",
        asic: Some("BM1391"),
        // S15 p.6 / ATA Level-2 p.38 (verbatim-identical): built-in group at
        // BM1391 pins 21/22, return via pins 23/24 through RI.
        asic_temp_pins: Some((21, 22)),
        asic_return_pins: Some((23, 24)),
        // p.6: "There are 4 temperature senses" — stated count.
        board_sensor_count: Some(4),
        sensor_positions: &[],
        sensor_part_candidates: &[],
        remote_diode_wiring: true,
        sensor_supply: None,
        // S15 p.11 / ATA p.47: PCB+chip of the 3 chains normally 25-95 C;
        // >95 C = heat-dissipation problem; <25 C = chain not working.
        normal_temp_range_c: Some((25, 95)),
        pcb_temp_alarm_c: None,
        fan_count: None,
        psu: None,
        citation: GuideCitation {
            guide_txt: "misc__S15_Maintenance_Guide.txt",
            page: 6,
        },
        notes: "ATA Level-2 training guide replicates the S15 chapter verbatim (pp.38/47).",
    },
    GuideThermalRow {
        model: "L3+",
        asic: Some("BM1485"),
        // L3+ p.8: sensor chip connects via BM1485 pins 6/7, returns via
        // pins 15/16 to the FPGA through RI.
        asic_temp_pins: Some((6, 7)),
        asic_return_pins: Some((15, 16)),
        board_sensor_count: None, // not stated
        sensor_positions: &[],
        sensor_part_candidates: &[],
        remote_diode_wiring: false, // wiring style not described beyond the pin path
        sensor_supply: None,
        normal_temp_range_c: None,
        pcb_temp_alarm_c: None,
        fan_count: None,
        psu: None,
        citation: GuideCitation {
            guide_txt: "misc__L3_Maintenance_Guide.txt",
            page: 8,
        },
        notes: "",
    },
    GuideThermalRow {
        model: "S17+",
        asic: None, // sensor section names TEMP_P/TEMP_N, not the ASIC
        asic_temp_pins: None,
        asic_return_pins: None,
        board_sensor_count: None, // not stated (placement figures image-only)
        sensor_positions: &[],
        sensor_part_candidates: &[],
        // p.14: "the connection status between the temperature-sensing and
        // the chip (TEMP_P; TEMP_N)" + dedicated temp-sensing VDD.
        remote_diode_wiring: true,
        sensor_supply: Some("VDD"),
        normal_temp_range_c: None,
        pcb_temp_alarm_c: None,
        fan_count: Some(4), // p.6: 3 hashboards + 1 control board + APW9+ + 4 cooling fans
        psu: Some("APW9+"),
        citation: GuideCitation {
            guide_txt: "s17__S17_Maintenance_Guide.txt",
            page: 14,
        },
        notes: "PDF title is 'S17+ Maintenance Guide'. Aging over-temp rule: keep aging ambient \
                < 40 C (p.17).",
    },
    GuideThermalRow {
        model: "T17e",
        asic: None,
        asic_temp_pins: None,
        asic_return_pins: None,
        board_sensor_count: None,
        sensor_positions: &[],
        sensor_part_candidates: &[],
        remote_diode_wiring: true, // p.13: TEMP_P/TEMP_N + temp-sensing VDD
        sensor_supply: Some("VDD"),
        normal_temp_range_c: None,
        pcb_temp_alarm_c: None,
        fan_count: Some(4), // p.6
        psu: Some("APW9+"),
        citation: GuideCitation {
            guide_txt: "s17__T17e_Maintenance_Guide.txt",
            page: 13,
        },
        notes: "Aging over-temp rule: keep aging ambient < 40 C (p.16).",
    },
    GuideThermalRow {
        model: "S19",
        asic: None,
        asic_temp_pins: None,
        asic_return_pins: None,
        // p.11: "the four temperature senses U4, R28~R30, U6, R31~R33, U7,
        // R34~R36, U8, R37~R39" — stated count 4, each with 3 matching
        // resistors, all on the back of the PCB, 3.3V supply.
        board_sensor_count: Some(4),
        sensor_positions: &["U4", "U6", "U7", "U8"],
        sensor_part_candidates: &[],
        remote_diode_wiring: true,
        sensor_supply: Some("3.3V"),
        normal_temp_range_c: None,
        // p.16: "The PCB temperature set by our monitoring system cannot
        // exceed 90 degrees. If it exceeds 90 degrees, the miner will alarm
        // and fail to work normally."
        pcb_temp_alarm_c: Some(90),
        fan_count: Some(4), // p.5: 3 hashboards + control board + APW12 + 4 cooling fans
        psu: Some("APW12"),
        citation: GuideCitation {
            guide_txt: "s19__S19_Maintenance_Guide.txt",
            page: 11,
        },
        notes: "",
    },
    GuideThermalRow {
        model: "S19 Pro",
        asic: None,
        asic_temp_pins: None,
        asic_return_pins: None,
        // p.10: four sensors U5 (R216/R219/R220), U7 (R221~R223),
        // U8 (R224~R226), U9 (R229~R231); back of PCB; 3.3V.
        board_sensor_count: Some(4),
        sensor_positions: &["U5", "U7", "U8", "U9"],
        sensor_part_candidates: &[],
        remote_diode_wiring: true,
        sensor_supply: Some("3.3V"),
        normal_temp_range_c: None,
        pcb_temp_alarm_c: Some(90), // p.16
        fan_count: Some(4),         // p.5
        psu: Some("APW12"),
        citation: GuideCitation {
            guide_txt: "s19__S19_Pro_Maintenance_Guide.txt",
            page: 10,
        },
        notes: "Sensor locations shown in Figures 4-4 and 5-13 (image-only).",
    },
    GuideThermalRow {
        model: "S19+",
        asic: None,
        asic_temp_pins: None,
        asic_return_pins: None,
        // p.9: four sensors U7 (R78/R80/R81), U8 (R83/R84/R88),
        // U9 (R92/R94/R95), U11 (R96~R98); back of PCB; 3.3V.
        board_sensor_count: Some(4),
        sensor_positions: &["U7", "U8", "U9", "U11"],
        sensor_part_candidates: &[],
        remote_diode_wiring: true,
        sensor_supply: Some("3.3V"),
        normal_temp_range_c: None,
        pcb_temp_alarm_c: Some(90), // p.13
        fan_count: Some(4),         // p.6
        psu: Some("APW12"),
        citation: GuideCitation {
            guide_txt: "s19__S19plus_Maintenance_Guide_1.txt",
            page: 9,
        },
        notes: "'Temperature IC on bottom side' diagram exists but is image-only (p.6).",
    },
    GuideThermalRow {
        model: "S19j Pro",
        asic: None,
        asic_temp_pins: None,
        asic_return_pins: None,
        // REFUSED, load-bearing: the guide's TOC promises "4. Phenomenon:
        // Abnormal temperature reading during test (PT2 mode)" on p.13, but
        // the body's item 4 is "Pattern NG" — the temperature section does
        // not exist, and the guide contains NO sensor placement/part/count
        // facts. The S19 Pro's U5/U7/U8/U9 row is a SIBLING board and is
        // not evidence for S19j Pro. Pinned None by test.
        board_sensor_count: None,
        sensor_positions: &[],
        sensor_part_candidates: &[],
        remote_diode_wiring: false,
        sensor_supply: None,
        normal_temp_range_c: None,
        pcb_temp_alarm_c: Some(90), // p.15: max PCB temp 90 C, alarm + cannot work
        fan_count: Some(4),         // p.7: 3 hash boards + control board + APW12 + 4 cooling fans
        psu: Some("APW12"),
        citation: GuideCitation {
            guide_txt: "s19__S19J_PRO_Maintenance_Guide.txt",
            page: 15,
        },
        notes: "TOC/body mismatch: promised temperature section absent. PT2 testing stops above \
                35 C ambient (p.13). PIC firmware named: 20200101-PIC1704-BM1398-V89.hex (p.9).",
    },
];

/// Fail-closed lookup by the guide's model title. Unknown model => `None`,
/// never a sibling row.
pub fn guide_thermal_for_model(model: &str) -> Option<&'static GuideThermalRow> {
    GUIDE_THERMAL_ROWS.iter().find(|r| r.model == model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensor_topology::all_sensor_topologies;
    use crate::vnish_thermal::all_vnish_models;

    /// Every row must carry a real citation into the extraction corpus.
    #[test]
    fn every_row_cites_a_guide_and_page() {
        for r in GUIDE_THERMAL_ROWS {
            assert!(
                r.citation.guide_txt.ends_with(".txt"),
                "{}: citation must name a corpus txt",
                r.model
            );
            assert!(r.citation.page > 0, "{}: page must be 1-based", r.model);
        }
    }

    #[test]
    fn lookup_is_fail_closed() {
        assert!(guide_thermal_for_model("S19").is_some());
        // Never guess: casing, sibling names, and non-corpus models refuse.
        assert!(guide_thermal_for_model("s19").is_none());
        assert!(guide_thermal_for_model("S19 XP").is_none());
        assert!(guide_thermal_for_model("S19k").is_none());
        assert!(guide_thermal_for_model("M60S").is_none());
    }

    /// S19 — s19__S19_Maintenance_Guide.txt p.11 (count/positions/supply),
    /// p.16 (90 C alarm), p.5 (4 fans, APW12).
    #[test]
    fn s19_row_matches_guide_p11_p16() {
        let r = guide_thermal_for_model("S19").expect("row");
        assert_eq!(
            r.board_sensor_count,
            Some(4),
            "p.11: four temperature senses"
        );
        assert_eq!(r.sensor_positions, &["U4", "U6", "U7", "U8"], "p.11");
        assert_eq!(r.sensor_supply, Some("3.3V"), "p.11");
        assert!(r.remote_diode_wiring, "p.11: matching resistors per sensor");
        assert_eq!(r.pcb_temp_alarm_c, Some(90), "p.16");
        assert_eq!(r.fan_count, Some(4), "p.5");
        assert_eq!(r.psu, Some("APW12"), "p.5");
        assert_eq!(r.citation.page, 11);
    }

    /// S19 Pro — s19__S19_Pro_Maintenance_Guide.txt p.10 / p.16 / p.5.
    #[test]
    fn s19_pro_row_matches_guide_p10_p16() {
        let r = guide_thermal_for_model("S19 Pro").expect("row");
        assert_eq!(r.board_sensor_count, Some(4), "p.10");
        assert_eq!(r.sensor_positions, &["U5", "U7", "U8", "U9"], "p.10");
        assert_eq!(r.pcb_temp_alarm_c, Some(90), "p.16");
        assert_eq!(r.fan_count, Some(4), "p.5");
    }

    /// S19+ — s19__S19plus_Maintenance_Guide_1.txt p.9 / p.13 / p.6.
    #[test]
    fn s19_plus_row_matches_guide_p9_p13() {
        let r = guide_thermal_for_model("S19+").expect("row");
        assert_eq!(r.board_sensor_count, Some(4), "p.9");
        assert_eq!(r.sensor_positions, &["U7", "U8", "U9", "U11"], "p.9");
        assert_eq!(r.pcb_temp_alarm_c, Some(90), "p.13");
    }

    /// S19j Pro — the guide's TOC-promised temperature section is ABSENT
    /// from its body (TOC line vs body item 4 = "Pattern NG"). The count
    /// must stay None: a sibling board's roster is not evidence. This is
    /// the mutation guard against backfilling from the S19 Pro row.
    #[test]
    fn s19j_pro_sensor_count_stays_refused() {
        let r = guide_thermal_for_model("S19j Pro").expect("row");
        assert_eq!(
            r.board_sensor_count, None,
            "s19__S19J_PRO_Maintenance_Guide.txt contains no sensor facts; do not backfill"
        );
        assert!(r.sensor_positions.is_empty());
        // Its non-sensor thermal facts ARE stated and must persist:
        assert_eq!(r.pcb_temp_alarm_c, Some(90), "p.15");
        assert_eq!(r.fan_count, Some(4), "p.7");
    }

    /// S9 — s9__S9_Maintenance_Guide.txt p.12 (pins, range, bus chips in
    /// notes) + p.22 (verbatim part roster). Count stays None (revision-
    /// ambiguous: p.12 single-circuit prose vs p.22 dual-sensor vs training
    /// p.46 U89+U102).
    #[test]
    fn s9_row_matches_guide_p12_p22() {
        let r = guide_thermal_for_model("S9").expect("row");
        assert_eq!(r.asic, Some("BM1387"));
        assert_eq!(r.asic_temp_pins, Some((15, 16)), "p.12");
        assert_eq!(r.asic_return_pins, Some((17, 18)), "p.12");
        assert_eq!(r.normal_temp_range_c, Some((65, 125)), "p.12");
        assert_eq!(r.board_sensor_count, None, "revision-ambiguous; REFUSED");
        // Verbatim p.22 roster, including the guide's own 'ECT218' spelling.
        assert_eq!(
            r.sensor_part_candidates,
            &["TMP451", "TMP461", "TMP421", "TMP431", "ECT218", "DRU1", "411B", "411C"]
        );
        assert_eq!(r.fan_count, Some(2), "p.24/28");
    }

    /// T9+ — verbatim pin capture including the first-party typo candidate.
    #[test]
    fn t9_plus_row_preserves_verbatim_pins() {
        let r = guide_thermal_for_model("T9+").expect("row");
        // VERBATIM p.12: "pin 2 and pin 16" — a typo candidate vs the
        // BM1387 pin map (15/16). If someone "corrects" the data they must
        // come through this test and the deliverable's tension #5.
        assert_eq!(r.asic_temp_pins, Some((2, 16)), "T9+ guide p.12 verbatim");
        assert_eq!(r.sensor_positions, &["U6"], "p.13: first chip of chain 2");
    }

    /// S11 — the corpus's first stated count of 2, with chip anchors.
    #[test]
    fn s11_row_matches_guide_p8() {
        let r = guide_thermal_for_model("S11").expect("row");
        assert_eq!(r.board_sensor_count, Some(2), "p.8: two sensor groups");
        assert_eq!(r.sensor_positions, &["U5", "U7"], "p.8");
        assert_eq!(r.asic, Some("BM1387BF"), "the S11 guide's own spelling");
    }

    /// S15 — BM1391 pins 21/22 -> 23/24, stated count 4, 25-95 C envelope.
    #[test]
    fn s15_row_matches_guide_p6_p11() {
        let r = guide_thermal_for_model("S15").expect("row");
        assert_eq!(r.asic, Some("BM1391"));
        assert_eq!(r.asic_temp_pins, Some((21, 22)), "p.6");
        assert_eq!(r.asic_return_pins, Some((23, 24)), "p.6");
        assert_eq!(
            r.board_sensor_count,
            Some(4),
            "p.6: 'There are 4 temperature senses'"
        );
        assert_eq!(r.normal_temp_range_c, Some((25, 95)), "p.11");
    }

    /// L3+ — BM1485 pins 6/7 -> 15/16.
    #[test]
    fn l3_plus_row_matches_guide_p8() {
        let r = guide_thermal_for_model("L3+").expect("row");
        assert_eq!(r.asic, Some("BM1485"));
        assert_eq!(r.asic_temp_pins, Some((6, 7)), "p.8");
        assert_eq!(r.asic_return_pins, Some((15, 16)), "p.8");
        assert_eq!(r.board_sensor_count, None, "not stated; REFUSED");
    }

    /// S17+/T17e — remote-diode wiring (TEMP_P/TEMP_N) + 4 fans + APW9+,
    /// counts refused.
    #[test]
    fn s17_family_rows_match_guides() {
        for model in ["S17+", "T17e"] {
            let r = guide_thermal_for_model(model).expect("row");
            assert!(r.remote_diode_wiring, "{model}: TEMP_P/TEMP_N stated");
            assert_eq!(r.board_sensor_count, None, "{model}: count not stated");
            assert_eq!(r.fan_count, Some(4), "{model}: p.6");
            assert_eq!(r.psu, Some("APW9+"), "{model}: p.6");
        }
    }

    // -----------------------------------------------------------------
    // Cross-corpus agreement (first-party guide vs the two desk corpora)
    // -----------------------------------------------------------------

    /// The guides' stated S19-family count (4) must agree with every VNish
    /// row for the same models. Model-code mapping: guide "S19" covers the
    /// VNish s19 / s19-88 / s19-126 rows; "S19 Pro" = s19pro; "S19+" =
    /// s19plus. (S19j Pro is deliberately absent — the guide refuses.)
    #[test]
    fn s19_family_guide_count_agrees_with_vnish_rows() {
        let cases: &[(&str, &[&str])] = &[
            ("S19", &["s19", "s19-88", "s19-126"]),
            ("S19 Pro", &["s19pro"]),
            ("S19+", &["s19plus"]),
        ];
        for (guide_model, vnish_codes) in cases {
            let guide_count = u16::from(
                guide_thermal_for_model(guide_model)
                    .expect("row")
                    .board_sensor_count
                    .expect("stated count"),
            );
            let mut matched = 0usize;
            for m in all_vnish_models() {
                if vnish_codes.contains(&m.model_code.as_str()) {
                    matched += 1;
                    assert_eq!(
                        m.expected_sensors_per_board(),
                        guide_count,
                        "{guide_model} guide count vs VNish {} ({})",
                        m.btm_model,
                        m.model_code
                    );
                }
            }
            assert!(
                matched > 0,
                "{guide_model}: no VNish rows matched — mapping drift"
            );
        }
    }

    /// The ePIC jig registry's universal 4-direct-sensor bank is now
    /// first-party corroborated for the S19 family: every registry SKU
    /// declares exactly 4 directly-addressed hashboard sensors, matching
    /// the guides' stated 4 for S19/S19 Pro/S19+.
    #[test]
    fn jig_registry_direct_bank_matches_first_party_four() {
        let guide_count = u16::from(
            guide_thermal_for_model("S19")
                .expect("row")
                .board_sensor_count
                .expect("stated"),
        );
        assert_eq!(guide_count, 4);
        for t in all_sensor_topologies() {
            assert_eq!(
                t.expected_direct_per_hashboard(),
                guide_count,
                "{}: jig direct bank vs first-party S19-family count",
                t.sku
            );
        }
    }

    /// The S9 verbatim part roster stays uncorrected: the guide's own
    /// "ECT218" spelling must survive (the in-tree LM90 decoder records
    /// ECT218 as unsourced; silently rewriting it to NCT218 here would
    /// fabricate a source).
    #[test]
    fn s9_part_roster_is_verbatim_not_normalized() {
        let r = guide_thermal_for_model("S9").expect("row");
        assert!(
            r.sensor_part_candidates.contains(&"ECT218"),
            "verbatim p.22"
        );
        assert!(
            !r.sensor_part_candidates.contains(&"NCT218"),
            "NCT218 is an interpretation, not the guide's text"
        );
    }
}
