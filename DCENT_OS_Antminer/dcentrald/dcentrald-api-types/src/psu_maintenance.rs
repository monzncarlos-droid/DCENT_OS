//! Round 17 B2 (2026-08-08) — first-party Bitmain PSU maintenance-guide
//! facts for the APW7 / APW8 / APW9 / APW9+ families (HAL-free, data only).
//!
//! # Source corpus (first-party Bitmain maintenance guides)
//!
//! :
//! - `APW7 Power Supply Maintenance Guide.pdf` (10 pages, version 2019.8.4)
//! - `APW8 Power Supply Maintenance Guide.pdf` (17 pages)
//! - `APW9 Power Supply Maintenance Guide.pdf` (17 pages)
//! - `APW9+Power Supply Maintenance Guide.pdf` (17 pages, edition 2019-09-05)
//!
//! Extraction note: the `_text/INDEX.json` extraction collides `APW9` and
//! `APW9+` onto one txt file (the `+` is stripped from the basename); the
//! on-disk `_text/psu__APW9_Power_Supply_Maintenance_Guide.txt` is the
//! **APW9+** text. Both PDFs were re-extracted separately for this module.
//!
//! # The headline finding (campaign axis 5, "PSU comms")
//!
//! - **APW8 / APW9 / APW9+ each carry a 4-pin signal terminal whose SDA/SCL
//!   is stated first-party to be "the I2C protocol", used to adjust the
//!   output voltage; EN is the enable signal, "effective in low level"**
//!   (APW8 guide p.5; APW9 guide p.5; APW9+ guide p.5). The main rail is
//!   regulated by an on-board PIC ("The main voltage output is controlled by
//!   the PIC port and the mining machine communication" — APW8 p.2-3, APW9
//!   p.2, APW9+ p.3). Shorting EN to GND with no I²C traffic produces the
//!   power-on default voltage (APW8: 16.32 V, p.4; APW9/APW9+: ~21.3 V,
//!   p.4/p.15).
//! - **APW7 has NO signal terminal at all** — the guide's appearance and
//!   parameter sections list only the AC C14 inlet, air in/outlet, and the
//!   DC output +/− (p.2-3). This is first-party evidence of **no digital
//!   control interface**, letting consumers fail closed honestly instead of
//!   probing a bus that does not exist on the PSU. The APW7 *does* output at
//!   AC apply (maintenance step 2.32, p.8: power on AC220V → output J6 shows
//!   12 V with no other stimulus).
//!
//! # What this module deliberately is NOT
//!
//! - **Not a protocol.** No I²C address, register, opcode, or frame layout
//!   appears in any of the four guides; none is invented here. The framed
//!   dialect in [`crate::psu_apw_protocol`] and the routing catalog in
//!   `dcentrald-silicon-profiles::psus` are separate evidence lines; known
//!   conflicts between them and this corpus are surfaced in
//!
//!   and are NOT resolved here.
//! - **Not a driver.** Data + lookup helpers only; nothing here can open a
//!   bus or energize anything.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Family roster
// ---------------------------------------------------------------------------

/// PSU families covered by the held first-party maintenance-guide corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuidePsuFamily {
    /// APW7 — single fixed 12 V output, no signal terminal.
    Apw7,
    /// APW8 — dual output; adjustable main rail (per-model band) + fixed
    /// 12.3 V aux. The guide's spec tables describe the 16.32-20.04 V
    /// S15/T15 variant; p.2-3 also lists sibling bands 8-9.2 V and 10-11 V.
    Apw8,
    /// APW9 — dual output; 14.5-21 V main + fixed 12.3 V aux; two AC inputs.
    Apw9,
    /// APW9+ — dual output; 14.5-21 V main + fixed 12.3 V aux; two AC
    /// inputs, per-input fan association (P1→F1, P2→F2).
    Apw9Plus,
}

/// Every guide-covered family, oldest first.
pub const ALL_GUIDE_FAMILIES: &[GuidePsuFamily] = &[
    GuidePsuFamily::Apw7,
    GuidePsuFamily::Apw8,
    GuidePsuFamily::Apw9,
    GuidePsuFamily::Apw9Plus,
];

// ---------------------------------------------------------------------------
// Control interface — the axis-5 payload
// ---------------------------------------------------------------------------

/// First-party classification of the PSU's digital control interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuideControlInterface {
    /// The guide documents **no signal terminal of any kind** — AC inlet and
    /// DC output only. First-party "none" evidence (APW7 p.2-3): consumers
    /// must fail closed instead of probing.
    NoneFirstParty,
    /// 4-pin signal terminal: SDA/SCL ("the I2C protocol", voltage adjust)
    /// + EN enable, **effective in low level**, + GND. Main rail regulated
    /// by an on-board PIC. No address/register/opcode is stated in the
    /// guide — wire-level protocol remains UNSPECIFIED by this corpus.
    I2cPicWithEnActiveLow,
}

// ---------------------------------------------------------------------------
// Protection semantics
// ---------------------------------------------------------------------------

/// How a protection trip clears, per the shared fault table (§2.5 of every
/// guide) and the APW7 electrical test table (APW7 p.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuideProtectionRecovery {
    /// Recovers by itself once the fault condition is removed.
    AutoRecovery,
    /// Enters a locked ("lock protection") state; requires AC re-power
    /// after the fault is removed.
    LatchedRequiresAcCycle,
}

/// The five-row fault-diagnosis table shared verbatim (modulo translation)
/// by all four guides (§2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GuideFaultRow {
    /// Row number in the guide's table (1-5).
    pub row: u8,
    /// Observable symptom.
    pub symptom: &'static str,
    /// First-party cause.
    pub cause: &'static str,
    /// Recovery semantics, where the table states them.
    pub recovery: Option<GuideProtectionRecovery>,
}

/// Shared §2.5 fault table. Same five rows in the APW7 (p.10), APW8
/// (p.16-17), APW9 (p.16-17), and APW9+ (p.16-17) guides.
pub const GUIDE_FAULT_TABLE: &[GuideFaultRow] = &[
    GuideFaultRow {
        row: 1,
        symptom: "fan not running, no 12 V output",
        cause: "AC-side supply abnormal (input line / grid)",
        recovery: None,
    },
    GuideFaultRow {
        row: 2,
        symptom: "fan runs normally, no main output",
        cause: "grid voltage too low (must be above 205 V) OR output \
                 short/overload -> lock protection state",
        recovery: Some(GuideProtectionRecovery::LatchedRequiresAcCycle),
    },
    GuideFaultRow {
        row: 3,
        symptom: "output stops for seconds, recovers, stops again cyclically",
        cause: "over-temperature protection (fan/duct/dust/derating)",
        recovery: Some(GuideProtectionRecovery::AutoRecovery),
    },
    GuideFaultRow {
        row: 4,
        symptom: "output normal, fan not running",
        cause: "fan blocked or faulty",
        recovery: None,
    },
    GuideFaultRow {
        row: 5,
        symptom: "suddenly no output, will not start again",
        cause: "overcurrent protection latched (fire-prevention lock)",
        recovery: Some(GuideProtectionRecovery::LatchedRequiresAcCycle),
    },
];

/// Minimum grid voltage the fault table requires before the PSU turns on
/// (fault row 2, all four guides): "confirm that the current voltage is
/// above 205 V, so that the power can be turned on".
pub const GUIDE_MIN_START_VAC: u16 = 205;

// ---------------------------------------------------------------------------
// Per-family spec
// ---------------------------------------------------------------------------

/// One DC output as printed in a guide's parameter table.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct GuideOutput {
    /// Minimum output voltage (V). Equal to `volts_max` for fixed rails.
    pub volts_min: f32,
    /// Maximum output voltage (V).
    pub volts_max: f32,
    /// Rated continuous current (A) at 220 V input, where printed.
    pub rated_current_a: Option<u16>,
}

/// First-party per-family record. Every field is verbatim from the named
/// guide/page; `None` means the guide does not print the value.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct GuidePsuSpec {
    /// Main (hash-power) output.
    pub main_output: GuideOutput,
    /// Auxiliary fixed control-board rail (PCIE terminal), if present.
    pub aux_output: Option<GuideOutput>,
    /// AC input range (V AC).
    pub ac_input_min_v: u16,
    pub ac_input_max_v: u16,
    /// Number of independent AC inlets (C14).
    pub ac_input_count: u8,
    /// Input undervoltage protection threshold band (V AC).
    pub input_uvp_vac: (u16, u16),
    /// Output overcurrent protection band (A) **as printed**. See
    /// `ocp_first_party_suspect` before trusting the APW9 value.
    pub ocp_a_as_printed: Option<(u16, u16)>,
    /// True when the printed OCP band is internally inconsistent with the
    /// same guide's rated current and matches a sibling guide's table
    /// verbatim (suspected copy-transplant). Do NOT treat such a band as
    /// measurement authority.
    pub ocp_first_party_suspect: bool,
    /// Digital control interface classification.
    pub control_interface: GuideControlInterface,
    /// Voltage produced when EN is shorted to GND with no I²C traffic
    /// (the guide's bench default), where applicable.
    pub en_short_default_v: Option<f32>,
    /// PFC bus (large-capacitor) working voltage band (V DC).
    pub pfc_bus_vdc: (u16, u16),
    /// Cooling fan count, where the guide states one explicitly (APW8:
    /// "two size-4028 high speed fans"; APW9/APW9+: three). `None` for
    /// APW7 — its guide only ever says "the DC fan" (singular) and never
    /// prints a count, so none is asserted.
    pub fan_count: Option<u8>,
    /// Guide + page citations backing this row.
    pub citation: &'static str,
}

impl GuidePsuFamily {
    /// First-party spec for this family.
    pub const fn spec(self) -> GuidePsuSpec {
        match self {
            // APW7 guide: p.3 parameter table (12.0 V, 150 A/1800 W @220 V,
            // 83.3 A/1000 W @110 V, UVP 80-89 V AC, OCP 150-200 A), p.4
            // input 200-264 V AC, p.6 VBUS 375-385 V, p.2-3 appearance
            // (AC input + output +/− only; no signal terminal).
            GuidePsuFamily::Apw7 => GuidePsuSpec {
                main_output: GuideOutput {
                    volts_min: 12.0,
                    volts_max: 12.5,
                    rated_current_a: Some(150),
                },
                aux_output: None,
                ac_input_min_v: 200,
                ac_input_max_v: 264,
                ac_input_count: 1,
                input_uvp_vac: (80, 89),
                ocp_a_as_printed: Some((150, 200)),
                ocp_first_party_suspect: false,
                control_interface: GuideControlInterface::NoneFirstParty,
                en_short_default_v: None,
                pfc_bus_vdc: (375, 385),
                fan_count: None,
                citation: "APW7 guide p.2-4 (params/appearance), p.6 (VBUS), \
                           p.9 (test criteria)",
            },
            // APW8 guide: p.3 (dual output, per-model bands 8-9.2 / 10-11 /
            // 16.32-20.04 V; spec tables are the S15/T15 variant), p.4-5
            // (appearance: one C14, two 4028 fans, 4-pin signal terminal
            // I²C+EN-active-low, PCIE 12 V aux), p.5-6 (OUT1 16.32-20.04 V
            // 95 A, power-on default 15.9-16.3 V; OUT2 12.3 V 5 A; UVP
            // 80-89 V AC; OCP 95-130 A), p.11 (PFC 370-380 V), p.4 (EN-GND
            // short -> default 16.32 V).
            GuidePsuFamily::Apw8 => GuidePsuSpec {
                main_output: GuideOutput {
                    volts_min: 16.32,
                    volts_max: 20.04,
                    rated_current_a: Some(95),
                },
                aux_output: Some(GuideOutput {
                    volts_min: 12.2,
                    volts_max: 12.4,
                    rated_current_a: Some(5),
                }),
                ac_input_min_v: 200,
                ac_input_max_v: 240,
                ac_input_count: 1,
                input_uvp_vac: (80, 89),
                ocp_a_as_printed: Some((95, 130)),
                ocp_first_party_suspect: false,
                control_interface: GuideControlInterface::I2cPicWithEnActiveLow,
                en_short_default_v: Some(16.32),
                pfc_bus_vdc: (370, 380),
                fan_count: Some(2),
                citation: "APW8 guide p.3-6 (params/appearance/signal \
                           terminal), p.11 (PFC), p.14 (J15 pins 4-5 = \
                           EN-GND)",
            },
            // APW9 guide: p.2-3 (dual output, 14.5-21 V 170 A + 12 V 12 A,
            // PIC-controlled, 3 fans), p.5 (two C14 inlets, 4-pin signal
            // terminal I²C+EN-active-low), p.5-6 (OUT1 3600 W; OUT2 12.3 V
            // 12 A; UVP 80-89 V AC; OCP printed 95-130 A — SUSPECT, see
            // flag), p.9 (large-capacitor 410-420 V), p.4 (EN short ->
            // default 21.32 V).
            GuidePsuFamily::Apw9 => GuidePsuSpec {
                main_output: GuideOutput {
                    volts_min: 14.5,
                    volts_max: 21.0,
                    rated_current_a: Some(170),
                },
                aux_output: Some(GuideOutput {
                    volts_min: 12.2,
                    volts_max: 12.4,
                    rated_current_a: Some(12),
                }),
                ac_input_min_v: 200,
                ac_input_max_v: 240,
                ac_input_count: 2,
                input_uvp_vac: (80, 89),
                // Printed verbatim on p.6, but identical to the APW8 table
                // row and physically inconsistent with the 170 A rating
                // (an OCP band *below* rated current). Suspected transplant
                // from the APW8 table — flagged, not laundered.
                ocp_a_as_printed: Some((95, 130)),
                ocp_first_party_suspect: true,
                control_interface: GuideControlInterface::I2cPicWithEnActiveLow,
                en_short_default_v: Some(21.32),
                pfc_bus_vdc: (410, 420),
                fan_count: Some(3),
                citation: "APW9 guide p.2-6 (params/appearance/signal \
                           terminal), p.9 (410-420 V), p.15 (J15 pins 4-5 \
                           EN-GND -> ~21.3 V)",
            },
            // APW9+ guide: p.3 (dual output 14.5-21 V 170 A + 12 V 12 A,
            // PIC-controlled), p.5 (two C14, three 4028 fans, 4-pin signal
            // terminal I²C+EN-active-low), p.6-7 (OUT1 3600 W; OUT2 12.3 V
            // 12 A; UVP 80-89 V AC; OCP 180-230 A; operating -20..50 °C),
            // p.9 (410-420 V), p.4 (EN short -> default 21.32 V), p.16
            // (per-input fan association P1→F1 / P2→F2).
            GuidePsuFamily::Apw9Plus => GuidePsuSpec {
                main_output: GuideOutput {
                    volts_min: 14.5,
                    volts_max: 21.0,
                    rated_current_a: Some(170),
                },
                aux_output: Some(GuideOutput {
                    volts_min: 12.2,
                    volts_max: 12.4,
                    rated_current_a: Some(12),
                }),
                ac_input_min_v: 200,
                ac_input_max_v: 240,
                ac_input_count: 2,
                input_uvp_vac: (80, 89),
                ocp_a_as_printed: Some((180, 230)),
                ocp_first_party_suspect: false,
                control_interface: GuideControlInterface::I2cPicWithEnActiveLow,
                en_short_default_v: Some(21.32),
                pfc_bus_vdc: (410, 420),
                fan_count: Some(3),
                citation: "APW9+ guide p.3-7 (params/appearance/signal \
                           terminal), p.9 (410-420 V), p.15 (EN-GND -> \
                           ~21.3 V), p.16 (P1→F1/P2→F2)",
            },
        }
    }

    /// Operator-facing label.
    pub const fn label(self) -> &'static str {
        match self {
            GuidePsuFamily::Apw7 => "APW7",
            GuidePsuFamily::Apw8 => "APW8",
            GuidePsuFamily::Apw9 => "APW9",
            GuidePsuFamily::Apw9Plus => "APW9+",
        }
    }
}

/// Model→PSU pairings stated in the first-party *model* maintenance guides
/// held in the same corpus (guide + page/line in the extraction text).
///
/// These are the corpus's own words, recorded so fleet code stops guessing:
/// - S9 / T9+ / L3+ / S9k / S9SE → APW3 / APW3++ (12 V, 133 A max)
/// - S11 → APW8 (output 10-11 V, 160 A max)
/// - S15 / T15 → APW8 (16.32-20.04 V; "regulated by the control panel",
///   "no output of APW8 without a control panel")
/// - S17+ / T17e → APW9+ ("APW9+_14.5V-21V_V2.01")
/// - S19 / S19 Pro / S19+ / S19j Pro → APW12 ("APW12_12V-15V_V1.2")
pub const GUIDE_MODEL_PSU_PAIRINGS: &[(&str, &str)] = &[
    ("S9", "APW3"),
    ("T9+", "APW3"),
    ("L3+", "APW3"),
    ("S9k", "APW3++"),
    ("S9SE", "APW3++"),
    ("S11", "APW8"),
    ("S15", "APW8"),
    ("T15", "APW8"),
    ("S17+", "APW9+"),
    ("T17e", "APW9+"),
    ("S19", "APW12"),
    ("S19 Pro", "APW12"),
    ("S19+", "APW12"),
    ("S19j Pro", "APW12"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apw7_has_no_control_interface_first_party() {
        // APW7 guide p.2-3: appearance lists AC input, air in/out, and
        // output +/− ONLY — no signal terminal exists on the enclosure.
        // p.8 step 2.32: output shows 12 V simply on AC apply.
        let s = GuidePsuFamily::Apw7.spec();
        assert_eq!(s.control_interface, GuideControlInterface::NoneFirstParty);
        assert!(s.aux_output.is_none());
        assert!(s.en_short_default_v.is_none());
    }

    #[test]
    fn apw8_9_9plus_declare_i2c_pic_with_en_active_low() {
        // APW8 p.5 / APW9 p.5 / APW9+ p.5, near-verbatim in each guide:
        // "The SDA/SCL is the I2C protocol, and can adjust the output
        // voltage of the power supply through I2C. EN is the enable signal
        // of the power supply ... which is effective in low level."
        for f in [
            GuidePsuFamily::Apw8,
            GuidePsuFamily::Apw9,
            GuidePsuFamily::Apw9Plus,
        ] {
            assert_eq!(
                f.spec().control_interface,
                GuideControlInterface::I2cPicWithEnActiveLow,
                "{} must declare the 4-pin I2C+EN terminal",
                f.label()
            );
        }
    }

    #[test]
    fn apw7_is_fixed_12v_1800w_class() {
        // APW7 guide p.3: DC 12.0 V, 150 A / 1800 W @220 V; voltage
        // accuracy 12.0-12.5 V. p.4: input 200-264 V AC (single inlet).
        let s = GuidePsuFamily::Apw7.spec();
        assert_eq!(s.main_output.volts_min, 12.0);
        assert_eq!(s.main_output.volts_max, 12.5);
        assert_eq!(s.main_output.rated_current_a, Some(150));
        assert_eq!(s.ac_input_count, 1);
        assert_eq!((s.ac_input_min_v, s.ac_input_max_v), (200, 264));
    }

    #[test]
    fn apw8_main_band_matches_s15_t15_variant() {
        // APW8 guide p.5: OUT1 16.32-20.04 V, 95 A; power-on default
        // 15.9-16.3 V; EN-GND short -> default 16.32 V (p.4).
        let s = GuidePsuFamily::Apw8.spec();
        assert_eq!(s.main_output.volts_min, 16.32);
        assert_eq!(s.main_output.volts_max, 20.04);
        assert_eq!(s.main_output.rated_current_a, Some(95));
        assert_eq!(s.en_short_default_v, Some(16.32));
    }

    #[test]
    fn apw8_aux_rail_is_12v3_5a() {
        // APW8 guide p.5-6: OUT2 DC 12.3 V (accuracy 12.2-12.4 V), 5 A,
        // PCIE terminal.
        let aux = GuidePsuFamily::Apw8.spec().aux_output.expect("aux");
        assert_eq!((aux.volts_min, aux.volts_max), (12.2, 12.4));
        assert_eq!(aux.rated_current_a, Some(5));
    }

    #[test]
    fn apw9_and_9plus_share_dual_output_dual_ac_shape() {
        // APW9 guide p.3/p.5-6 and APW9+ guide p.3/p.6: 14.5-21 V 170 A
        // main + 12.3 V 12 A aux, two AC inlets, three fans.
        for f in [GuidePsuFamily::Apw9, GuidePsuFamily::Apw9Plus] {
            let s = f.spec();
            assert_eq!(
                (s.main_output.volts_min, s.main_output.volts_max),
                (14.5, 21.0)
            );
            assert_eq!(s.main_output.rated_current_a, Some(170));
            let aux = s.aux_output.expect("aux");
            assert_eq!(aux.rated_current_a, Some(12));
            assert_eq!(s.ac_input_count, 2);
            assert_eq!(s.fan_count, Some(3));
            assert_eq!(s.en_short_default_v, Some(21.32));
            assert_eq!(s.pfc_bus_vdc, (410, 420));
        }
    }

    #[test]
    fn apw9_printed_ocp_is_flagged_suspect_transplant() {
        // APW9 guide p.6 prints OCP 95-130 A — verbatim-identical to the
        // APW8 table and BELOW the 170 A rated current. Physically
        // inconsistent; suspected copy-transplant. The flag must stay so
        // no consumer treats the printed band as measurement authority.
        let s = GuidePsuFamily::Apw9.spec();
        assert_eq!(s.ocp_a_as_printed, Some((95, 130)));
        assert!(s.ocp_first_party_suspect);
        // The APW9+ guide fixes it: 180-230 A (p.6), consistent with 170 A.
        let sp = GuidePsuFamily::Apw9Plus.spec();
        assert_eq!(sp.ocp_a_as_printed, Some((180, 230)));
        assert!(!sp.ocp_first_party_suspect);
    }

    #[test]
    fn all_families_share_input_uvp_80_89_vac() {
        // Identical "Input undervoltage protection value 80-89V AC" row in
        // all four guides (APW7 p.4, APW8 p.6, APW9 p.6, APW9+ p.6).
        for f in ALL_GUIDE_FAMILIES {
            assert_eq!(f.spec().input_uvp_vac, (80, 89), "{}", f.label());
        }
    }

    #[test]
    fn fault_table_latch_semantics_pinned() {
        // §2.5 of every guide: OCP is a fire-prevention LOCK (row 5) and
        // short/overload locks too (row 2) — both need AC re-power; OTP
        // (row 3) auto-recovers cyclically. These semantics drive honest
        // dashboard fault decode: a latched PSU cannot be "retried" in
        // software.
        assert_eq!(GUIDE_FAULT_TABLE.len(), 5);
        assert_eq!(
            GUIDE_FAULT_TABLE[1].recovery,
            Some(GuideProtectionRecovery::LatchedRequiresAcCycle)
        );
        assert_eq!(
            GUIDE_FAULT_TABLE[2].recovery,
            Some(GuideProtectionRecovery::AutoRecovery)
        );
        assert_eq!(
            GUIDE_FAULT_TABLE[4].recovery,
            Some(GuideProtectionRecovery::LatchedRequiresAcCycle)
        );
        assert_eq!(GUIDE_MIN_START_VAC, 205);
    }

    #[test]
    fn pfc_bus_bands_differ_by_generation() {
        // APW7 p.6: 375-385 V; APW8 p.11: 370-380 V; APW9 p.9 / APW9+
        // p.9: 410-420 V. Useful desk cross-check: the APW12 constant in
        // `crate::apw_dual_output` is also 410-420 V.
        assert_eq!(GuidePsuFamily::Apw7.spec().pfc_bus_vdc, (375, 385));
        assert_eq!(GuidePsuFamily::Apw8.spec().pfc_bus_vdc, (370, 380));
        assert_eq!(GuidePsuFamily::Apw9.spec().pfc_bus_vdc, (410, 420));
        assert_eq!(
            GuidePsuFamily::Apw9.spec().pfc_bus_vdc,
            (
                crate::apw_dual_output::APW12_PFC_BUS_VOLTAGE_MIN as u16,
                crate::apw_dual_output::APW12_PFC_BUS_VOLTAGE_MAX as u16
            )
        );
    }

    #[test]
    fn model_pairings_come_from_model_guides() {
        // S11 guide p.1 (line 14 of extraction): "APW8 power supply
        // (output 10V—11V, 160A Max)". S15 guide: S15 PSU is APW8 and
        // "there will be no output of APW8 without a control panel".
        // S17+/T17e guides name APW9+; S19-family guides name APW12.
        let find = |m: &str| {
            GUIDE_MODEL_PSU_PAIRINGS
                .iter()
                .find(|(model, _)| *model == m)
                .map(|(_, psu)| *psu)
        };
        assert_eq!(find("S11"), Some("APW8"));
        assert_eq!(find("S15"), Some("APW8"));
        assert_eq!(find("S17+"), Some("APW9+"));
        assert_eq!(find("T17e"), Some("APW9+"));
        assert_eq!(find("S19j Pro"), Some("APW12"));
        assert_eq!(find("S9"), Some("APW3"));
    }

    #[test]
    fn en_active_low_families_do_not_power_on_at_ac_apply() {
        // S15 guide (extraction line 46): "there will be no output of APW8
        // without a control panel to regulate the voltage" — the main rail
        // needs EN low (or I²C). Pin: every I²C+EN family has an EN-short
        // default voltage documented, i.e. main output is EN-gated, NOT
        // AC-apply. (APW7, the only NoneFirstParty family, IS AC-apply.)
        for f in ALL_GUIDE_FAMILIES {
            let s = f.spec();
            match s.control_interface {
                GuideControlInterface::I2cPicWithEnActiveLow => {
                    assert!(s.en_short_default_v.is_some(), "{}", f.label())
                }
                GuideControlInterface::NoneFirstParty => {
                    assert!(s.en_short_default_v.is_none(), "{}", f.label())
                }
            }
        }
    }

    #[test]
    fn spec_serializes() {
        for f in ALL_GUIDE_FAMILIES {
            let json = serde_json::to_string(&f.spec()).unwrap();
            assert!(json.contains("control_interface"));
        }
    }
}
