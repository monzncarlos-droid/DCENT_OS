//! First-party fault & diagnostic knowledge layer, transcribed from Bitmain's
//! own maintenance-training corpus.
//!
//! # What this is
//!
//! A **pure, declarative, read-only** reference layer that encodes the fault
//! taxonomy, the symptom → suspect → test → remedy chains, and the per-signal
//! reference measurement values that Bitmain teaches its own certified repair
//! technicians ("Ant Training Academy", ATA). Every entry cites the source
//! guide and page so a downstream consumer — a dashboard repair panel, a
//! toolbox `dcent diagnose` explainer, or `repair_advisor` provenance — can show
//! the operator *why* a suspect is ranked where it is, with a first-party
//! citation.
//!
//! # What this is NOT (binding constraints — R17 team B9)
//!
//! * **It never energizes silicon, opens a bus, changes a thermal trip, or gates
//!   mining.** There is no hardware path in this file; it is `const` data and
//!   pure functions over that data.
//! * **A training-guide measurement tolerance is REFERENCE DATA, not a runtime
//!   threshold.** The Fluke-15B+ diode/voltage values in [`signal_reference`]
//!   describe what a technician expects to read with a bench multimeter on a
//!   *powered test jig*; they must never be wired into a protection, shutdown,
//!   voltage, or fan path. The board-health grading thresholds live in
//!   `board_health.rs` and are deliberately separate.
//! * **Manufacturing WRITE operations are out of scope and REFUSED by policy.**
//!   The training material documents EEPROM writes, PIC/dsPIC reflash, serial
//!   provisioning, PT1 pass-marker stamping, and voltage/offset writes. Those
//!   are catalogued in the H6 census (15 forbidden write-ops) and are *not*
//!   modelled here. This layer is the read-only half only.
//!
//! # Sources (SHA-256-pinned in )
//!
//! * `training__ATA_Level_2_Maintenance_Guide.txt` (96 pp) — "Secondary
//!   Maintenance Training Material", Shenzhen CLOUDIC / Bitmain 2019.11.
//! * `training__Primary_Maintenance_Training_Material.txt` (66 pp).
//! * `misc__17_19_Diode_Resistance_Voltage_Values_for_reference.txt` (3 pp) —
//!   the cross-model Fluke-15B+ diode/voltage reference table.
//!
//! Page numbers below are the **PDF page** (the `===== PAGE N =====` marker in
//! the extracted text), not the printed folio.

use serde::{Deserialize, Serialize};

/// A first-party citation: which held guide, and which PDF page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuideRef {
    /// Source guide short id (see module docs for the full filename).
    pub guide: Guide,
    /// PDF page number (the `===== PAGE N =====` marker).
    pub page: u16,
}

impl GuideRef {
    const fn new(guide: Guide, page: u16) -> Self {
        Self { guide, page }
    }
}

/// The held first-party guides this layer transcribes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Guide {
    /// `training__ATA_Level_2_Maintenance_Guide.txt` (Secondary Maintenance).
    AtaLevel2,
    /// `training__Primary_Maintenance_Training_Material.txt`.
    PrimaryTraining,
    /// `misc__17_19_Diode_Resistance_Voltage_Values_for_reference.txt`.
    Diode1719Reference,
}

impl Guide {
    /// Stable extracted-text basename (without extension).
    pub fn text_basename(self) -> &'static str {
        match self {
            Self::AtaLevel2 => "training__ATA_Level_2_Maintenance_Guide",
            Self::PrimaryTraining => "training__Primary_Maintenance_Training_Material",
            Self::Diode1719Reference => "misc__17_19_Diode_Resistance_Voltage_Values_for_reference",
        }
    }
}

/// How Bitmain classifies where a fault is fixed. Field-reversible actions are
/// always attempted first in the training material ("cut the cheapest reversible
/// path before returning a board").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Repairability {
    /// Reversible on-site action: re-plug/reseat a cable, reset, reflash the
    /// control board, clean dust, lower ambient. No soldering.
    FieldReversible,
    /// On-site component-level rework: replace a fan/PSU, or (for a certified
    /// L1/L2 tech with a jig) reflow/replace a chip, LDO, or MOSFET.
    FieldComponentLevel,
    /// Beyond field scope in the training material: return to factory /
    /// after-sales (e.g. PIC-abnormal kernel-log states, high-CRC boards that
    /// survive cable + PSU + reset).
    BoardReturn,
}

impl Repairability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FieldReversible => "field_reversible",
            Self::FieldComponentLevel => "field_component_level",
            Self::BoardReturn => "board_return",
        }
    }
}

/// The observable-symptom classes Bitmain names in its troubleshooting tables
/// and single-board-test sections. These mirror the *training* taxonomy, not
/// DCENT_OS's internal [`crate::repair_advisor::SuspectedComponent`] (which is a
/// per-ChipMap *cause* classifier). The two axes are complementary — see the B9
/// deliverable for the cross-walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymptomClass {
    /// "The mining machine is not powered." (whole unit dead)
    NotPowered,
    /// "No data in the background or 0 hashrate."
    ZeroHashrate,
    /// "The mining machine has insufficient board hashrate." (a chain low)
    InsufficientBoardHashrate,
    /// "Mining machine's red light flashes."
    RedLightFlashing,
    /// "Run for a period of time with fewer/partial chips; restart to recover."
    IntermittentChipLoss,
    /// High-temperature protection → 0 hashrate (thermal).
    HighTempProtection,
    /// Single-board jig test reports `ASIC=0` (whole board silent on the jig).
    SingleBoardAsicZero,
    /// Single-board jig test reports `ASIC=xx` (broken chain at chip xx).
    BrokenChain,
    /// Single-board `Pattern=NG` / a chip's hashrate below the per-core floor.
    LowHashrateChip,
}

impl SymptomClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotPowered => "not_powered",
            Self::ZeroHashrate => "zero_hashrate",
            Self::InsufficientBoardHashrate => "insufficient_board_hashrate",
            Self::RedLightFlashing => "red_light_flashing",
            Self::IntermittentChipLoss => "intermittent_chip_loss",
            Self::HighTempProtection => "high_temp_protection",
            Self::SingleBoardAsicZero => "single_board_asic_zero",
            Self::BrokenChain => "broken_chain",
            Self::LowHashrateChip => "low_hashrate_chip",
        }
    }
}

/// One ranked step in a symptom → suspect → test → remedy chain, exactly as the
/// training material orders it (cheapest reversible action first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticStep {
    /// What the technician suspects at this step.
    pub suspect: &'static str,
    /// The observable test / measurement to confirm or rule it out.
    pub test: &'static str,
    /// The remedy if the test confirms the suspect.
    pub remedy: &'static str,
    /// Where the fix falls in Bitmain's field-vs-return model.
    pub repairability: Repairability,
    /// First-party citation.
    pub cite: GuideRef,
}

/// The ordered symptom → suspect → test → remedy chain Bitmain teaches for a
/// given observable symptom. Order is the *field workflow* order (attempt the
/// cheapest reversible step first), which is a different axis from
/// `repair_advisor`'s structural-confidence ordering.
pub fn diagnostic_chain(symptom: SymptomClass) -> &'static [DiagnosticStep] {
    use Repairability::{BoardReturn, FieldComponentLevel, FieldReversible};
    match symptom {
        // ATA/Primary "Troubleshooting Table V1.0", row 1.
        SymptomClass::NotPowered => {
            const {
                &[
                    DiagnosticStep {
                        suspect: "power supply / power cable not seated or unpowered",
                        test: "confirm PSU and power cable are plugged in and powered",
                        remedy: "re-plug the line",
                        repairability: FieldReversible,
                        cite: GuideRef::new(Guide::AtaLevel2, 21),
                    },
                    DiagnosticStep {
                        suspect: "faulty PSU (no 12V on the 6-pin)",
                        test: "measure the PSU 6-pin line for 12V output with a multimeter",
                        remedy: "replace the faulty power supply",
                        repairability: FieldComponentLevel,
                        cite: GuideRef::new(Guide::AtaLevel2, 21),
                    },
                    DiagnosticStep {
                        suspect: "control board / computing board burnout",
                        test: "inspect the control panel and computing board for burnout marks",
                        remedy: "replace the control panel",
                        repairability: FieldComponentLevel,
                        cite: GuideRef::new(Guide::AtaLevel2, 21),
                    },
                ]
            }
        }
        // ATA/Primary Troubleshooting Table row 4 + Kernel-Log troubleshooting.
        SymptomClass::ZeroHashrate => {
            const {
                &[
            DiagnosticStep {
                suspect: "fan cable unplugged or fan faulty (control panel gates on tach)",
                test: "check the fan cable / pull the Kernel Log to the bottom for a fan fault",
                remedy: "re-plug the fan cable or replace the fan",
                repairability: FieldReversible,
                cite: GuideRef::new(Guide::AtaLevel2, 21),
            },
            DiagnosticStep {
                suspect: "network fault (cannot reach the pool)",
                test: "check the machine can ping the pool; Network→Diagnostics Ping",
                remedy: "network troubleshooting or replace the pool",
                repairability: FieldReversible,
                cite: GuideRef::new(Guide::AtaLevel2, 21),
            },
            DiagnosticStep {
                suspect: "computing-board cable not inserted (a board reports absent)",
                test: "Kernel Log: only boards 5,6 shown when 5,6,7 expected = a cable is unseated",
                remedy: "reseat the computing-board cable; if a board reports 0 chips, replace PSU then repair/return",
                repairability: FieldReversible,
                cite: GuideRef::new(Guide::AtaLevel2, 20),
            },
        ]
            }
        }
        // ATA/Primary Troubleshooting Table row 5.
        SymptomClass::InsufficientBoardHashrate => {
            const {
                &[
                    DiagnosticStep {
                        suspect: "6-pin power line / computing-board cable loose",
                        test: "confirm the 6-pin power line and cable are plugged in firmly",
                        remedy: "re-plug the line",
                        repairability: FieldReversible,
                        cite: GuideRef::new(Guide::AtaLevel2, 22),
                    },
                    DiagnosticStep {
                        suspect: "faulty PSU",
                        test: "check whether the power supply is faulty",
                        remedy: "replace the faulty power supply",
                        repairability: FieldComponentLevel,
                        cite: GuideRef::new(Guide::AtaLevel2, 22),
                    },
                ]
            }
        }
        // ATA/Primary Troubleshooting Table row 6.
        SymptomClass::RedLightFlashing => {
            const {
                &[
                    DiagnosticStep {
                        suspect: "network abnormal",
                        test: "check whether the network is normal / fan is faulty",
                        remedy: "restore the network; check the fan",
                        repairability: FieldReversible,
                        cite: GuideRef::new(Guide::AtaLevel2, 22),
                    },
                    DiagnosticStep {
                        suspect: "high-temperature protection",
                        test: "check whether the machine is in high-temperature protection",
                        remedy: "lower the ambient temperature and clean the dust",
                        repairability: FieldReversible,
                        cite: GuideRef::new(Guide::AtaLevel2, 22),
                    },
                ]
            }
        }
        // ATA/Primary Troubleshooting Table rows 7 & 8.
        SymptomClass::IntermittentChipLoss => {
            const {
                &[
                    DiagnosticStep {
                        suspect: "PSU instability",
                        test: "check the power supply",
                        remedy: "replace the power supply",
                        repairability: FieldComponentLevel,
                        cite: GuideRef::new(Guide::AtaLevel2, 22),
                    },
                    DiagnosticStep {
                        suspect: "poor grounding (chassis leakage damaging boards)",
                        test:
                            "measure chassis-to-shelf voltage (recommend <1V); check grounding <4Ω",
                        remedy: "conduct proper grounding",
                        repairability: FieldReversible,
                        cite: GuideRef::new(Guide::AtaLevel2, 22),
                    },
                    DiagnosticStep {
                        suspect: "network device / main network",
                        test: "check the network",
                        remedy: "replace the network device or change the main network",
                        repairability: FieldReversible,
                        cite: GuideRef::new(Guide::AtaLevel2, 22),
                    },
                ]
            }
        }
        // ATA Daily Inspection §4 + Kernel-Log high-temp state + p47 (>100°C protects).
        SymptomClass::HighTempProtection => {
            const {
                &[
            DiagnosticStep {
                suspect: "high ambient / warm-air recirculation at the inlet",
                test: "measure air-inlet temp (target 10-25°C; >30°C trips protection)",
                remedy: "lower ambient; add hot/cold isolation; fix warm-air return",
                repairability: FieldReversible,
                cite: GuideRef::new(Guide::AtaLevel2, 9),
            },
            DiagnosticStep {
                suspect: "dust blocking the cooling fins / fallen cooling fin",
                test: "inspect fins for dust and for detached heatsinks (chain temp <25°C = board dead; >95°C = poor cooling)",
                remedy: "clean dust with an antistatic brush; re-glue fallen fins",
                repairability: FieldReversible,
                cite: GuideRef::new(Guide::AtaLevel2, 47),
            },
            DiagnosticStep {
                suspect: "fan return-speed insufficient (even if visibly spinning)",
                test: "Kernel Log reports low fan speed → replace the flagged fan",
                remedy: "replace the fan",
                repairability: FieldComponentLevel,
                cite: GuideRef::new(Guide::AtaLevel2, 20),
            },
        ]
            }
        }
        // ATA S15 §VI.1 / S17 §VI.6.1 single-board jig ASIC=0.
        SymptomClass::SingleBoardAsicZero => {
            const {
                &[
            DiagnosticStep {
                suspect: "jig cable to computing board not seated",
                test: "confirm jig cable and computing board make good contact",
                remedy: "reseat the jig cable",
                repairability: FieldReversible,
                cite: GuideRef::new(Guide::AtaLevel2, 37),
            },
            DiagnosticStep {
                suspect: "domain has no core voltage (DC-DC MOS off / PIC firmware lost)",
                test: "measure inter-domain voltage (S15 J4-J5=18.36V, S17 J6-J7=18.5V); check Q7/Q8/Q9/Q11 pin4=0V and Q10 pin1=3.3V",
                remedy: "if Q10 lacks 3.3V the U3-PIC has lost firmware or has no power → reflash/replace PIC (bench)",
                repairability: FieldComponentLevel,
                cite: GuideRef::new(Guide::AtaLevel2, 37),
            },
            DiagnosticStep {
                suspect: "RI signal / per-domain 1.8V LDO fault or dead chip",
                test: "from the last chip's test point measure RI≈1.8V; measure LDO 1.8V (≈0.868K to GND) and 0.8V (≈41.4Ω)",
                remedy: "replace a burned LDO; if RI still absent with sound solder, replace the chip",
                repairability: FieldComponentLevel,
                cite: GuideRef::new(Guide::AtaLevel2, 38),
            },
        ]
            }
        }
        // ATA S15/S17 single-board jig ASIC=xx (broken chain) + Primary §IX.2.
        SymptomClass::BrokenChain => {
            const {
                &[
            DiagnosticStep {
                suspect: "the chip at index xx (or xx+1) is the break point",
                test: "measure CLK/CO/BO/RST voltage and ground impedance at chips xx and xx+1 (see signal reference)",
                remedy: "replace the abnormal chip (watch for resistance oxidation)",
                repairability: FieldComponentLevel,
                cite: GuideRef::new(Guide::AtaLevel2, 51),
            },
            DiagnosticStep {
                suspect: "locate the break by bisection when voltages look normal",
                test: "short the CO of the midpoint chip to ground; dichotomy on which half the count changes",
                remedy: "replace the located faulty chip",
                repairability: FieldComponentLevel,
                cite: GuideRef::new(Guide::PrimaryTraining, 54),
            },
        ]
            }
        }
        // ATA S15 §V.3 / Primary §IX.3 low-hashrate / Pattern=NG.
        SymptomClass::LowHashrateChip => {
            const {
                &[
            DiagnosticStep {
                suspect: "a specific weak/binned chip below the per-chip hashrate floor",
                test: "single-board jig prints per-chip hashrate; normal is above ~1900 (S15); IP-LOG shows low-frequency chips",
                remedy: "replace the low chip",
                repairability: FieldComponentLevel,
                cite: GuideRef::new(Guide::PrimaryTraining, 55),
            },
            DiagnosticStep {
                suspect: "board survives cable + PSU + reset with high CRC / low chain hashrate",
                test: "Kernel Log CRC error high with insufficient hashrate",
                remedy: "return to factory or bench-repair",
                repairability: BoardReturn,
                cite: GuideRef::new(Guide::AtaLevel2, 18),
            },
        ]
            }
        }
    }
}

/// A per-signal bench reference reading for BM139x-class hashboards.
///
/// **REFERENCE DATA ONLY.** These are Fluke-15B+ diode-mode resistance readings
/// and powered-jig node voltages that a technician compares against a known-good
/// board. They are NOT runtime thresholds and must never be wired into any
/// protection, voltage, thermal, or fan path. Values vary with meter and board
/// batch (the source table says so explicitly).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SignalReference {
    /// Signal / node name (BI/BO, RST, RX/RI, TX/CO, CLK, LDO rails).
    pub node: &'static str,
    /// Diode-mode resistance-to-ground reading (ohms), if the guide gives one.
    pub diode_ohms: Option<&'static str>,
    /// Expected node voltage on a powered jig, if the guide gives one.
    pub voltage: Option<&'static str>,
    /// First-party citation.
    pub cite: GuideRef,
}

/// Cross-model per-signal reference readings from the 17/19 Diode/Voltage
/// reference sheet (Fluke 15B+). Keyed by the guide's model label. The S17 /
/// S17+ / T17 / T17+ family share one column; S17e / T17e share another; S19 /
/// S19 Pro share a third. This function returns the representative set for a
/// model label; unknown labels return an empty slice (fail closed, no guess).
///
/// REFERENCE DATA ONLY — see [`SignalReference`].
pub fn signal_reference(model_label: &str) -> &'static [SignalReference] {
    // The reference sheet is 3 pages; the S17 family is p1, S17e/T17e p1-2,
    // S19/S19 Pro p2-3.
    const S17_FAMILY: &[SignalReference] = &[
        SignalReference {
            node: "BI/BO",
            diode_ohms: Some("1200±20"),
            voltage: Some("0"),
            cite: GuideRef::new(Guide::Diode1719Reference, 1),
        },
        SignalReference {
            node: "RST",
            diode_ohms: Some("1200±20"),
            voltage: Some("1.7±0.1"),
            cite: GuideRef::new(Guide::Diode1719Reference, 1),
        },
        SignalReference {
            node: "RX/RI",
            diode_ohms: Some("420±20"),
            voltage: Some("1.7±0.1"),
            cite: GuideRef::new(Guide::Diode1719Reference, 1),
        },
        SignalReference {
            node: "TX/CO",
            diode_ohms: Some("1200±20"),
            voltage: Some("1.7±0.1"),
            cite: GuideRef::new(Guide::Diode1719Reference, 1),
        },
        SignalReference {
            node: "CLK",
            diode_ohms: Some("1200±20"),
            voltage: Some("0.7-0.9"),
            cite: GuideRef::new(Guide::Diode1719Reference, 1),
        },
        SignalReference {
            node: "LDO 1.8V",
            diode_ohms: Some("400±20"),
            voltage: None,
            cite: GuideRef::new(Guide::Diode1719Reference, 1),
        },
        SignalReference {
            node: "LDO 0.8V",
            diode_ohms: Some("20±5"),
            voltage: None,
            cite: GuideRef::new(Guide::Diode1719Reference, 1),
        },
    ];
    const S17E_FAMILY: &[SignalReference] = &[
        SignalReference {
            node: "BI/BO",
            diode_ohms: Some("1015±50"),
            voltage: Some("0"),
            cite: GuideRef::new(Guide::Diode1719Reference, 1),
        },
        SignalReference {
            node: "RST",
            diode_ohms: Some("970±50"),
            voltage: Some("1.7±0.1"),
            cite: GuideRef::new(Guide::Diode1719Reference, 1),
        },
        SignalReference {
            node: "RX/RI",
            diode_ohms: Some("500±50"),
            voltage: Some("1.7±0.1"),
            cite: GuideRef::new(Guide::Diode1719Reference, 1),
        },
        SignalReference {
            node: "TX/CO",
            diode_ohms: Some("1015±50"),
            voltage: Some("1.7±0.1"),
            cite: GuideRef::new(Guide::Diode1719Reference, 1),
        },
        SignalReference {
            node: "CLK",
            diode_ohms: Some("1015±50"),
            voltage: Some("0.7-0.9"),
            cite: GuideRef::new(Guide::Diode1719Reference, 1),
        },
        SignalReference {
            node: "LDO 1.8V",
            diode_ohms: Some("400±50"),
            voltage: None,
            cite: GuideRef::new(Guide::Diode1719Reference, 1),
        },
        SignalReference {
            node: "LDO 0.8V",
            diode_ohms: Some("25±5"),
            voltage: None,
            cite: GuideRef::new(Guide::Diode1719Reference, 1),
        },
    ];
    const S19_FAMILY: &[SignalReference] = &[
        SignalReference {
            node: "BI/BO",
            diode_ohms: Some("1220±20"),
            voltage: Some("0"),
            cite: GuideRef::new(Guide::Diode1719Reference, 2),
        },
        SignalReference {
            node: "RST",
            diode_ohms: Some("980±20"),
            voltage: Some("1.7±0.1"),
            cite: GuideRef::new(Guide::Diode1719Reference, 2),
        },
        SignalReference {
            node: "RX/RI",
            diode_ohms: Some("390±20"),
            voltage: Some("1.7±0.1"),
            cite: GuideRef::new(Guide::Diode1719Reference, 2),
        },
        SignalReference {
            node: "TX/CO",
            diode_ohms: Some("1220±20"),
            voltage: Some("1.7±0.1"),
            cite: GuideRef::new(Guide::Diode1719Reference, 2),
        },
        SignalReference {
            node: "CLK",
            diode_ohms: Some("1220±20"),
            voltage: Some("0.7-0.9"),
            cite: GuideRef::new(Guide::Diode1719Reference, 2),
        },
        SignalReference {
            node: "1.8V",
            diode_ohms: Some("440±20"),
            voltage: None,
            cite: GuideRef::new(Guide::Diode1719Reference, 2),
        },
        SignalReference {
            node: "0.8V",
            diode_ohms: Some("20±5"),
            voltage: None,
            cite: GuideRef::new(Guide::Diode1719Reference, 2),
        },
    ];
    match model_label {
        "S17" | "S17+" | "T17" | "T17+" => S17_FAMILY,
        "S17e" | "T17e" => S17E_FAMILY,
        "S19" | "S19 Pro" => S19_FAMILY,
        _ => &[],
    }
}

/// Voltage-domain topology as stated in the ATA training prose (chips per domain
/// × domains), for the two chip families the training material actually covers.
///
/// REFERENCE DATA ONLY. This is *training-guide* topology, kept separate from
/// `repair_advisor::default_voltage_domain_size` (which is RE-verified autotuner
/// topology for the modern chips). Provided so a consumer can cite Bitmain's own
/// number for the S15/S17-era boards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainTopology {
    pub board: &'static str,
    pub chip: &'static str,
    pub domains: u8,
    pub chips_per_domain: u8,
    pub total_chips: u16,
    pub cite: GuideRef,
}

/// Training-guide voltage-domain topologies (S15/S17 era only).
pub fn training_domain_topologies() -> &'static [DomainTopology] {
    // `GuideRef::new` is a `const fn`, and Rust does NOT const-promote function
    // calls — even `const fn` ones — so a bare `&[...]` here is a reference to a
    // temporary (E0515). An inline `const { }` block gives the array a `'static`
    // const allocation, which is what the signature promises.
    const {
        &[
            // ATA §Chapter V, S15: "12 voltage domains connected in series, each
            // domain has 5 BM1391, and the entire board has 60 BM1391 chips."
            DomainTopology {
                board: "S15",
                chip: "BM1391",
                domains: 12,
                chips_per_domain: 5,
                total_chips: 60,
                cite: GuideRef::new(Guide::AtaLevel2, 29),
            },
            // ATA §Chapter VI, S17: "48 chips, and 12 voltage domains".
            DomainTopology {
                board: "S17",
                chip: "BM1397/BM1396",
                domains: 12,
                chips_per_domain: 4,
                total_chips: 48,
                cite: GuideRef::new(Guide::AtaLevel2, 47),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_symptom_has_at_least_one_cited_step() {
        for symptom in [
            SymptomClass::NotPowered,
            SymptomClass::ZeroHashrate,
            SymptomClass::InsufficientBoardHashrate,
            SymptomClass::RedLightFlashing,
            SymptomClass::IntermittentChipLoss,
            SymptomClass::HighTempProtection,
            SymptomClass::SingleBoardAsicZero,
            SymptomClass::BrokenChain,
            SymptomClass::LowHashrateChip,
        ] {
            let chain = diagnostic_chain(symptom);
            assert!(
                !chain.is_empty(),
                "{} has no diagnostic steps",
                symptom.as_str()
            );
            for step in chain {
                assert!(step.cite.page > 0, "uncited step in {}", symptom.as_str());
                assert!(!step.suspect.is_empty());
                assert!(!step.test.is_empty());
                assert!(!step.remedy.is_empty());
            }
        }
    }

    #[test]
    fn not_powered_leads_with_the_reversible_cable_reseat() {
        // ATA Level-2 Troubleshooting Table V1.0, row 1, p21: the first taught
        // action for a dead unit is "re-plug the line", not a component swap.
        // This is the first-party basis for connector/cable reseat being the
        // cheapest-first field remedy across the whole taxonomy.
        let chain = diagnostic_chain(SymptomClass::NotPowered);
        assert_eq!(chain[0].repairability, Repairability::FieldReversible);
        assert_eq!(chain[0].remedy, "re-plug the line");
        assert_eq!(chain[0].cite, GuideRef::new(Guide::AtaLevel2, 21));
    }

    #[test]
    fn zero_hashrate_models_the_unseated_computing_board_cable() {
        // ATA Level-2 Kernel-Log troubleshooting, p20: "only boards 5,6 shown"
        // = a computing-board cable is unseated. This is the first-party
        // corroboration that a chain going dark can be a connector fault, not
        // silicon — the same signature repair_advisor calls ChainBreak.
        let chain = diagnostic_chain(SymptomClass::ZeroHashrate);
        let cable = chain
            .iter()
            .find(|s| s.suspect.contains("computing-board cable"))
            .expect("computing-board cable step present");
        assert_eq!(cable.cite, GuideRef::new(Guide::AtaLevel2, 20));
        assert_eq!(cable.repairability, Repairability::FieldReversible);
    }

    #[test]
    fn single_board_asic_zero_cites_the_jig_domain_voltages() {
        // ATA Level-2 p37: S15 J4-J5=18.36V, S17 J6-J7=18.5V jig test voltages,
        // and the Q10/PIC-firmware-loss decision rule.
        let chain = diagnostic_chain(SymptomClass::SingleBoardAsicZero);
        assert!(chain.iter().any(|s| s.test.contains("18.5V")));
        assert!(chain
            .iter()
            .any(|s| s.suspect.contains("PIC firmware lost")));
    }

    #[test]
    fn signal_reference_is_family_grouped_and_fails_closed() {
        // 17/19 Diode/Voltage reference sheet: S17 family shares one column.
        let s17 = signal_reference("S17");
        assert_eq!(signal_reference("S17+"), s17);
        assert_eq!(signal_reference("T17"), s17);
        // S17e is a distinct column (1015±50 vs 1200±20).
        assert_ne!(signal_reference("S17e"), s17);
        // Unknown model → empty, never a guessed value.
        assert!(signal_reference("S21").is_empty());
    }

    #[test]
    fn signal_reference_clk_matches_the_sheet() {
        // CLK on S17 family: diode 1200±20, voltage 0.7-0.9 (reference sheet p1).
        let s17 = signal_reference("S17");
        let clk = s17.iter().find(|r| r.node == "CLK").expect("CLK present");
        assert_eq!(clk.diode_ohms, Some("1200±20"));
        assert_eq!(clk.voltage, Some("0.7-0.9"));
        assert_eq!(clk.cite, GuideRef::new(Guide::Diode1719Reference, 1));
    }

    #[test]
    fn training_domain_topology_matches_ata_prose() {
        // ATA Level-2 p29 (S15) and p47 (S17).
        let tops = training_domain_topologies();
        let s15 = tops.iter().find(|t| t.board == "S15").unwrap();
        assert_eq!(
            (s15.domains, s15.chips_per_domain, s15.total_chips),
            (12, 5, 60)
        );
        assert_eq!(s15.cite, GuideRef::new(Guide::AtaLevel2, 29));
        let s17 = tops.iter().find(|t| t.board == "S17").unwrap();
        assert_eq!(
            (s17.domains, s17.chips_per_domain, s17.total_chips),
            (12, 4, 48)
        );
    }

    #[test]
    fn repairability_partitions_field_vs_return() {
        // At least one whole-taxonomy remedy is board-return (high-CRC survivor),
        // and the cheapest-first steps are reversible — the training's field-vs-
        // return boundary is represented.
        let mut saw_reversible = false;
        let mut saw_return = false;
        for symptom in [SymptomClass::NotPowered, SymptomClass::LowHashrateChip] {
            for step in diagnostic_chain(symptom) {
                match step.repairability {
                    Repairability::FieldReversible => saw_reversible = true,
                    Repairability::BoardReturn => saw_return = true,
                    Repairability::FieldComponentLevel => {}
                }
            }
        }
        assert!(saw_reversible && saw_return);
    }
}
