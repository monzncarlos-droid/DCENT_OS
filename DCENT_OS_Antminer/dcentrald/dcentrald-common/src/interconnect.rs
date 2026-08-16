//! Declarative hashboard ↔ control-board interconnect descriptions (Round 17, B4).
//!
//!  axis 7 ("interconnect") had no owner: `plug_detect_gpio` existed as
//! a bare per-chain number with no physical model behind it, and
//! `repair_advisor.rs` names "connector seating / ribbon" as its #1 suspect
//! class without any data about the connector it suspects. This module is the
//! data layer that fills that gap from the **first-party Bitmain maintenance
//! guide corpus** (INDEX.json
//! carries the per-PDF sha256).
//!
//! # Evidence discipline (do not regress)
//!
//! * Every table here carries a [`GuideRef`] citation (guide + page). The
//!   pinouts come from **figures** (PCB renders / schematic captures), read
//!   from 150-DPI page renders — page numbers below are the render pages.
//! * A pin the guide does not label is **absent** from the map, never guessed.
//!   Partial maps say so via [`IoConnectorDesc::complete`].
//! * Presence/plug-detect polarity is only representable as
//!   [`PresencePolarity::ActiveHigh`] because that is the only polarity any
//!   guide states ("this signal raises 10K resistance to 3.3V by hashboard, so
//!   this pin is high level when IO signal is plugged"). If a future corpus
//!   yields an active-low presence pin, add the variant *with its citation* —
//!   do not flip an existing entry (the `gpio437` lesson: an unmeasured
//!   polarity is worse than none).
//! * S17/S19-family connector maps are **deliberately partial** (pins 3/7/8
//!   only). Their guides never state the PLUG pin; extrapolating the S15-era
//!   template would be inference, and this module refuses it. Consequently
//!   those rows carry `presence: None` even though the *runtime* am2 path has
//!   control-board-side sysfs plug GPIOs — those numbers are our own probe
//!   evidence and live in `dcentrald-hal`, not in this corpus-backed layer.
//!
//! This module is pure data + pure functions. It performs no I/O, owns no
//! hardware, and is wired to nothing that switches power.

/// Citation into the maintenance-guide corpus.
///
/// `pdf` is the path under ;
/// `sha256_prefix` is the leading hex of the PDF sha256 recorded in
/// `_text/INDEX.json` (enough to disambiguate; the full hash lives there).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuideRef {
    pub pdf: &'static str,
    pub page: u16,
    pub sha256_prefix: &'static str,
}

/// What a connector pin does, as the guide states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinFunction {
    /// Ground.
    Gnd,
    /// I²C data of the DC-DC PIC (and, where stated, the on-board EEPROM).
    I2cSda,
    /// I²C clock.
    I2cScl,
    /// Hashboard presence ("identification") pin. See [`PresenceFact`].
    PlugDetect,
    /// PIC address bit (`0` = A0, `1` = A1, `2` = A2).
    PicAddrBit(u8),
    /// EEPROM address bit (S11 wording: "the eeprom address signal").
    EepromAddrBit(u8),
    /// Work/command UART into chip 01 for the given chain domain on the board.
    Txd { domain: u8 },
    /// Response UART back from the last chip for the given chain domain.
    Rxd { domain: u8 },
    /// Chain reset (3.3 V connector end, level-shifted down on the board).
    Rst { domain: u8 },
    /// 3.3 V supplied by the control board (powers PIC/EEPROM and the
    /// PLUG0 pull-up).
    Supply3v3,
    /// Hashboard ID pin (T9+ pins 6/16).
    BoardId,
    /// "EN" on the S15-era map. Name only — the guide states no direction,
    /// polarity, or driver. Never actuate on the basis of this entry.
    EnableNameOnly,
    /// Explicitly marked NC by the guide.
    NotConnected,
}

/// Presence-pin polarity. Only the guide-stated variant exists on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresencePolarity {
    /// HIGH at the control board = hashboard present/mated.
    ActiveHigh,
}

/// Pull topology behind a presence pin, as stated by the guides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresencePull {
    /// 10 K on the **hashboard** up to the control-board-supplied 3.3 V rail.
    /// (All six stating guides use this topology.)
    HashboardPullUp10kTo3v3,
}

/// A fully-cited plug-detect fact. Constructible only with a citation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresenceFact {
    pub pin: u8,
    pub polarity: PresencePolarity,
    pub pull: PresencePull,
    pub source: GuideRef,
}

/// Declarative IO ("signal cable") connector description for one model family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoConnectorDesc {
    /// Model family label, matching maintenance-guide naming.
    pub model_family: &'static str,
    /// Mechanical identity as the guide words it.
    pub mechanical: &'static str,
    /// Hashboard-side designator where the guide names it (`J1`, `J4`).
    pub board_designator: Option<&'static str>,
    /// Total pin count of the shell.
    pub pin_count: u8,
    /// Stated pins only. Pins the guide leaves unlabelled are absent.
    pub pins: &'static [(u8, PinFunction)],
    /// True iff every one of `pin_count` pins is stated (unlabelled pads make
    /// a map incomplete even when the guide shows the whole shell).
    pub complete: bool,
    /// Plug-detect fact, present only where the guide states pin + polarity.
    pub presence: Option<PresenceFact>,
    /// Where the map comes from.
    pub source: GuideRef,
}

// ─── Citations ───────────────────────────────────────────────────────────────

const S9_GUIDE_P8: GuideRef = GuideRef {
    pdf: "s9/S9 Maintenance Guide.pdf",
    page: 8,
    sha256_prefix: "1aad109a",
};
const T9P_GUIDE_P8: GuideRef = GuideRef {
    pdf: "s9/T9+ Maintenance Guide.pdf",
    page: 8,
    sha256_prefix: "9d0018fa",
};
const L3P_GUIDE_P5: GuideRef = GuideRef {
    pdf: "misc/L3+ Maintenance Guide.pdf",
    page: 5,
    sha256_prefix: "8a96cfa2",
};
const S11_GUIDE_P6: GuideRef = GuideRef {
    pdf: "misc/S11Maintenance Guide.pdf",
    page: 6,
    sha256_prefix: "36f3fd26",
};
const S15_GUIDE_P4: GuideRef = GuideRef {
    pdf: "misc/S15 Maintenance Guide.pdf",
    page: 4,
    sha256_prefix: "4496807c",
};
const S9K_GUIDE_P3: GuideRef = GuideRef {
    pdf: "s9/S9k S9SE Maintenance Guide.pdf",
    page: 3,
    sha256_prefix: "52f84613",
};
const S17P_GUIDE_P5: GuideRef = GuideRef {
    pdf: "s17/S17+ Maintenance Guide.pdf",
    page: 5,
    sha256_prefix: "7ae5388e",
};
const T17E_GUIDE_P5: GuideRef = GuideRef {
    pdf: "s17/T17e Maintenance Guide.pdf",
    page: 5,
    sha256_prefix: "b908604b",
};
const S19_GUIDE_P5: GuideRef = GuideRef {
    pdf: "s19/S19 Maintenance Guide.pdf",
    page: 5,
    sha256_prefix: "1ca49f8f",
};
const S19PRO_GUIDE_P5: GuideRef = GuideRef {
    pdf: "s19/S19 Pro Maintenance Guide.pdf",
    page: 5,
    sha256_prefix: "5a8c9f4f",
};
const S19PLUS_GUIDE_P6: GuideRef = GuideRef {
    pdf: "s19/S19plus_Maintenance_Guide (1).pdf",
    page: 6,
    sha256_prefix: "2b699ed3",
};
const S19JPRO_GUIDE_P7: GuideRef = GuideRef {
    pdf: "s19/S19J-PRO Maintenance Guide.pdf",
    page: 7,
    sha256_prefix: "a6b7f94a",
};
const DIODE_REF_GUIDE: GuideRef = GuideRef {
    pdf: "misc/17_19 Diode（Resistance）_Voltage Values for reference.pdf",
    page: 1,
    sha256_prefix: "564fcf41",
};

// ─── S9-era 18-pin map (S9 / L3+ / S11; T9+ extends it to 2x12) ─────────────

/// S9 Fig 8 "Each Pin Definition of IO" (2X9 pitch 2.0 PHSD 90°, J1
/// "Header 2x9"). Pins 17/18 are shown but unlabelled/auto-named → absent.
pub const S9_IO_PINS: &[(u8, PinFunction)] = &[
    (1, PinFunction::Gnd),
    (2, PinFunction::Gnd),
    (3, PinFunction::I2cSda),
    (4, PinFunction::I2cScl),
    (5, PinFunction::PlugDetect),
    (6, PinFunction::PicAddrBit(2)),
    (7, PinFunction::PicAddrBit(1)),
    (8, PinFunction::PicAddrBit(0)),
    (9, PinFunction::Gnd),
    (10, PinFunction::Gnd),
    (11, PinFunction::Txd { domain: 0 }),
    (12, PinFunction::Rxd { domain: 0 }),
    (13, PinFunction::Gnd),
    (14, PinFunction::Gnd),
    (15, PinFunction::Rst { domain: 0 }),
    (16, PinFunction::Supply3v3),
];

/// S11 variant: same positions, but pins 6/7/8 are "the eeprom address
/// signal" (AT24C02 U4 in Figure 9) rather than PIC address.
pub const S11_IO_PINS: &[(u8, PinFunction)] = &[
    (1, PinFunction::Gnd),
    (2, PinFunction::Gnd),
    (3, PinFunction::I2cSda),
    (4, PinFunction::I2cScl),
    (5, PinFunction::PlugDetect),
    (6, PinFunction::EepromAddrBit(2)),
    (7, PinFunction::EepromAddrBit(1)),
    (8, PinFunction::EepromAddrBit(0)),
    (9, PinFunction::Gnd),
    (10, PinFunction::Gnd),
    (11, PinFunction::Txd { domain: 0 }),
    (12, PinFunction::Rxd { domain: 0 }),
    (13, PinFunction::Gnd),
    (14, PinFunction::Gnd),
    (15, PinFunction::Rst { domain: 0 }),
    (16, PinFunction::Supply3v3),
];

/// T9+ Fig 11 (2×12, 24-pin; three chain domains on one hashboard).
///
/// The Fig 11 PCB render is authoritative for 7/8/21/22: the same page's
/// prose contradicts itself (assigns 21/22 to both TXD2/RXD2 and RST1/RST2);
/// the render shows TXD2/RXD2 at 7/8 and RST1/RST2 at 21/22.
pub const T9PLUS_IO_PINS: &[(u8, PinFunction)] = &[
    (1, PinFunction::Gnd),
    (2, PinFunction::Gnd),
    (3, PinFunction::I2cSda),
    (4, PinFunction::I2cScl),
    (5, PinFunction::PlugDetect),
    (6, PinFunction::BoardId),
    (7, PinFunction::Txd { domain: 2 }),
    (8, PinFunction::Rxd { domain: 2 }),
    (9, PinFunction::Gnd),
    (10, PinFunction::Gnd),
    (11, PinFunction::Txd { domain: 0 }),
    (12, PinFunction::Rxd { domain: 0 }),
    (13, PinFunction::Gnd),
    (14, PinFunction::Gnd),
    (15, PinFunction::Rst { domain: 0 }),
    (16, PinFunction::BoardId),
    (17, PinFunction::Txd { domain: 1 }),
    (18, PinFunction::Rxd { domain: 1 }),
    (19, PinFunction::Gnd),
    (20, PinFunction::Gnd),
    (21, PinFunction::Rst { domain: 1 }),
    (22, PinFunction::Rst { domain: 2 }),
    (23, PinFunction::Gnd),
    (24, PinFunction::Gnd),
];

// ─── S15-era 18-pin map (S15; taught as current-gen by ATA Level-2 p35) ─────

/// S15 "Definition of IO seat pin" + J1 `CON_2p0_2X9_R` schematic.
/// Same 2x9 2.0 mm shell as S9 — **different electrical map**.
pub const S15_IO_PINS: &[(u8, PinFunction)] = &[
    (1, PinFunction::NotConnected),
    (2, PinFunction::EnableNameOnly),
    (3, PinFunction::Rst { domain: 0 }),
    (4, PinFunction::Supply3v3),
    (5, PinFunction::Gnd),
    (6, PinFunction::Gnd),
    (7, PinFunction::Txd { domain: 0 }),
    (8, PinFunction::Rxd { domain: 0 }),
    (9, PinFunction::Gnd),
    (10, PinFunction::Gnd),
    (11, PinFunction::PicAddrBit(1)),
    (12, PinFunction::PicAddrBit(0)),
    (13, PinFunction::PlugDetect),
    (14, PinFunction::PicAddrBit(2)),
    (15, PinFunction::I2cSda),
    (16, PinFunction::I2cScl),
    (17, PinFunction::Gnd),
    (18, PinFunction::Gnd),
];

/// The three pins the S17/S19-family guides state, and nothing more.
/// (TX in pin 7 → chip 01; RX return pin 8; RST in pin 3.)
pub const S17_S19_FAMILY_STATED_PINS: &[(u8, PinFunction)] = &[
    (3, PinFunction::Rst { domain: 0 }),
    (7, PinFunction::Txd { domain: 0 }),
    (8, PinFunction::Rxd { domain: 0 }),
];

/// S19j Pro deviation: its guide routes "RST **and CI**" from pin 3 and RX
/// from pin 8, contradicting every sibling guide (CI at pin 7). Desk-
/// unresolvable → only the two uncontested pins are declared.
pub const S19JPRO_STATED_PINS: &[(u8, PinFunction)] = &[
    (3, PinFunction::Rst { domain: 0 }),
    (8, PinFunction::Rxd { domain: 0 }),
];

const MECH_2X9: &str = "2x9 pitch 2.0 mm PHSD 90-degree in-line dual row";
const MECH_2X12: &str = "2x12 pitch 2.0 mm PHSD 90-degree in-line dual row";

/// The registry. Order: guide corpus order, complete maps first.
pub const IO_CONNECTORS: &[IoConnectorDesc] = &[
    IoConnectorDesc {
        model_family: "s9",
        mechanical: MECH_2X9,
        board_designator: Some("J1"),
        pin_count: 18,
        pins: S9_IO_PINS,
        complete: false, // pins 17/18 unlabelled in Fig 8
        presence: Some(PresenceFact {
            pin: 5,
            polarity: PresencePolarity::ActiveHigh,
            pull: PresencePull::HashboardPullUp10kTo3v3,
            source: S9_GUIDE_P8,
        }),
        source: S9_GUIDE_P8,
    },
    IoConnectorDesc {
        model_family: "l3+",
        mechanical: MECH_2X9,
        board_designator: None,
        pin_count: 18,
        pins: S9_IO_PINS, // byte-identical signal set per L3+ Fig 8
        complete: false,
        presence: Some(PresenceFact {
            pin: 5,
            polarity: PresencePolarity::ActiveHigh,
            pull: PresencePull::HashboardPullUp10kTo3v3,
            source: L3P_GUIDE_P5,
        }),
        source: L3P_GUIDE_P5,
    },
    IoConnectorDesc {
        model_family: "s11",
        mechanical: MECH_2X9,
        board_designator: None,
        pin_count: 18,
        pins: S11_IO_PINS,
        complete: false,
        presence: Some(PresenceFact {
            pin: 5,
            polarity: PresencePolarity::ActiveHigh,
            pull: PresencePull::HashboardPullUp10kTo3v3,
            source: S11_GUIDE_P6,
        }),
        source: S11_GUIDE_P6,
    },
    IoConnectorDesc {
        model_family: "t9+",
        mechanical: MECH_2X12,
        board_designator: None,
        pin_count: 24,
        pins: T9PLUS_IO_PINS,
        complete: true,
        presence: Some(PresenceFact {
            pin: 5,
            polarity: PresencePolarity::ActiveHigh,
            pull: PresencePull::HashboardPullUp10kTo3v3,
            source: T9P_GUIDE_P8,
        }),
        source: T9P_GUIDE_P8,
    },
    IoConnectorDesc {
        model_family: "s15",
        mechanical: MECH_2X9,
        board_designator: Some("J1"),
        pin_count: 18,
        pins: S15_IO_PINS,
        complete: true,
        presence: Some(PresenceFact {
            pin: 13,
            polarity: PresencePolarity::ActiveHigh,
            pull: PresencePull::HashboardPullUp10kTo3v3,
            source: S15_GUIDE_P4,
        }),
        source: S15_GUIDE_P4,
    },
    IoConnectorDesc {
        model_family: "s9k/s9se",
        mechanical: MECH_2X9,
        board_designator: Some("J4"),
        pin_count: 18,
        pins: S17_S19_FAMILY_STATED_PINS, // CO pin 7, RI pin 8, NRSTO pin 3
        complete: false,
        presence: None, // not stated for S9k/S9SE
        source: S9K_GUIDE_P3,
    },
    IoConnectorDesc {
        model_family: "s17+",
        mechanical: MECH_2X9,
        board_designator: None,
        pin_count: 18,
        pins: S17_S19_FAMILY_STATED_PINS,
        complete: false,
        presence: None,
        source: S17P_GUIDE_P5,
    },
    IoConnectorDesc {
        model_family: "t17e",
        mechanical: MECH_2X9,
        board_designator: None,
        pin_count: 18,
        pins: S17_S19_FAMILY_STATED_PINS,
        complete: false,
        presence: None,
        source: T17E_GUIDE_P5,
    },
    IoConnectorDesc {
        model_family: "s19",
        mechanical: MECH_2X9,
        board_designator: None,
        pin_count: 18,
        pins: S17_S19_FAMILY_STATED_PINS,
        complete: false,
        presence: None,
        source: S19_GUIDE_P5,
    },
    IoConnectorDesc {
        model_family: "s19pro",
        mechanical: MECH_2X9,
        board_designator: None,
        pin_count: 18,
        pins: S17_S19_FAMILY_STATED_PINS,
        complete: false,
        presence: None,
        source: S19PRO_GUIDE_P5,
    },
    IoConnectorDesc {
        model_family: "s19+",
        mechanical: MECH_2X9,
        board_designator: None,
        pin_count: 18,
        pins: S17_S19_FAMILY_STATED_PINS,
        complete: false,
        presence: None,
        source: S19PLUS_GUIDE_P6,
    },
    IoConnectorDesc {
        model_family: "s19jpro",
        mechanical: MECH_2X9,
        board_designator: None,
        pin_count: 18,
        pins: S19JPRO_STATED_PINS,
        complete: false,
        presence: None,
        source: S19JPRO_GUIDE_P7,
    },
];

/// Look up the corpus-backed IO connector description for a model family.
pub fn io_connector_for(model_family: &str) -> Option<&'static IoConnectorDesc> {
    IO_CONNECTORS
        .iter()
        .find(|c| c.model_family == model_family)
}

// ─── Diode (resistance) + voltage reference values ───────────────────────────

/// Signal-cable-adjacent test points named by the 17/19 reference sheet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalTestPoint {
    BiBo,
    Rst,
    RxRi,
    TxCo,
    Clk,
    Ldo1v8,
    Ldo0v8,
}

/// One model's diode-scale references (Fluke 15B+; the sheet's own caveat:
/// values vary with meter and board batch — take actual results as standard).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiodeReferenceRow {
    pub model: &'static str,
    /// (nominal, tolerance) diode-scale readings, sheet units, in
    /// [`SignalTestPoint`] order BI/BO, RST, RX/RI, TX/CO, CLK, LDO1.8, LDO0.8.
    pub diode: [(u16, u16); 7],
    pub source: GuideRef,
}

/// The complete 17/19 reference sheet.
pub const DIODE_REFERENCE: &[DiodeReferenceRow] = &[
    DiodeReferenceRow {
        model: "s17",
        diode: [
            (1200, 20),
            (1200, 20),
            (420, 20),
            (1200, 20),
            (1200, 20),
            (400, 20),
            (20, 5),
        ],
        source: DIODE_REF_GUIDE,
    },
    DiodeReferenceRow {
        model: "s17+",
        diode: [
            (1200, 20),
            (1200, 20),
            (420, 20),
            (1200, 20),
            (1200, 20),
            (400, 20),
            (20, 5),
        ],
        source: DIODE_REF_GUIDE,
    },
    DiodeReferenceRow {
        model: "s17e",
        diode: [
            (1015, 50),
            (970, 50),
            (500, 50),
            (1015, 50),
            (1015, 50),
            (400, 50),
            (25, 5),
        ],
        source: DIODE_REF_GUIDE,
    },
    DiodeReferenceRow {
        model: "t17",
        diode: [
            (1200, 20),
            (1200, 20),
            (420, 20),
            (1200, 20),
            (1200, 20),
            (400, 20),
            (20, 5),
        ],
        source: GuideRef {
            page: 2,
            ..DIODE_REF_GUIDE
        },
    },
    DiodeReferenceRow {
        model: "t17+",
        diode: [
            (1200, 20),
            (1200, 20),
            (420, 20),
            (1200, 20),
            (1200, 20),
            (400, 20),
            (20, 5),
        ],
        source: GuideRef {
            page: 2,
            ..DIODE_REF_GUIDE
        },
    },
    DiodeReferenceRow {
        model: "t17e",
        diode: [
            (1015, 50),
            (970, 50),
            (500, 50),
            (1015, 50),
            (1015, 50),
            (400, 50),
            (25, 5),
        ],
        source: GuideRef {
            page: 2,
            ..DIODE_REF_GUIDE
        },
    },
    DiodeReferenceRow {
        model: "s19",
        diode: [
            (1220, 20),
            (980, 20),
            (390, 20),
            (1220, 20),
            (1220, 20),
            (440, 20),
            (20, 5),
        ],
        source: GuideRef {
            page: 2,
            ..DIODE_REF_GUIDE
        },
    },
    DiodeReferenceRow {
        model: "s19pro",
        diode: [
            (1220, 20),
            (980, 20),
            (390, 20),
            (1220, 20),
            (1220, 20),
            (440, 20),
            (20, 5),
        ],
        source: GuideRef {
            page: 3,
            ..DIODE_REF_GUIDE
        },
    },
];

/// Look up the diode reference row for a model.
pub fn diode_reference_for(model: &str) -> Option<&'static DiodeReferenceRow> {
    DIODE_REFERENCE.iter().find(|r| r.model == model)
}

// ─── Repair-product safety fact ──────────────────────────────────────────────

/// Signal-cable handling order, stated near-identically by the S19, S19 Pro,
/// S19+ and S19j Pro guides: connect negative PSU copper, then positive, then
/// the signal cable LAST; remove the signal cable FIRST, then positive, then
/// negative. "In case of failing to follow this order, it is very easy to
/// cause damage to U1 and U2" (the chain level-shifter ICs). Any
/// reseat-the-ribbon repair advice on S19-class hardware must sequence this
/// way. Sources: S19 p2, S19 Pro p1, S19+ p2, S19J-PRO p3.
pub const SIGNAL_CABLE_RESEAT_ORDER: &str = "S19-class reseat order: power down; remove signal \
     cable FIRST, then positive copper, then negative copper. Reconnect negative, positive, then \
     signal cable LAST. Violating this order damages the chain level-shifters (U1/U2).";

#[cfg(test)]
mod tests {
    use super::*;

    /// Completeness gate: every registered connector cites a guide page, and
    /// its pin list is consistent with its own completeness claim.
    #[test]
    fn every_connector_is_cited_and_consistent() {
        for c in IO_CONNECTORS {
            assert!(
                !c.source.pdf.is_empty(),
                "{}: missing citation",
                c.model_family
            );
            assert!(
                c.source.page > 0,
                "{}: page must be 1-based",
                c.model_family
            );
            assert!(
                !c.source.sha256_prefix.is_empty(),
                "{}: missing sha256 prefix",
                c.model_family
            );
            // No duplicate pin numbers; every pin within the shell.
            let mut seen = std::collections::BTreeSet::new();
            for &(pin, _) in c.pins {
                assert!(
                    pin >= 1 && pin <= c.pin_count,
                    "{}: pin {} out of shell",
                    c.model_family,
                    pin
                );
                assert!(
                    seen.insert(pin),
                    "{}: duplicate pin {}",
                    c.model_family,
                    pin
                );
            }
            if c.complete {
                assert_eq!(
                    c.pins.len(),
                    c.pin_count as usize,
                    "{}: claims complete but does not state every pin",
                    c.model_family
                );
            } else {
                assert!(
                    c.pins.len() < c.pin_count as usize,
                    "{}: states every pin but claims incomplete",
                    c.model_family
                );
            }
        }
    }

    /// A presence fact must point at a pin the map actually declares as
    /// [`PinFunction::PlugDetect`], and must carry its own citation.
    #[test]
    fn presence_facts_are_backed_by_a_declared_plug_pin() {
        for c in IO_CONNECTORS {
            if let Some(p) = c.presence {
                assert!(
                    c.pins
                        .iter()
                        .any(|&(pin, f)| pin == p.pin && f == PinFunction::PlugDetect),
                    "{}: presence fact pin {} has no PlugDetect entry",
                    c.model_family,
                    p.pin
                );
                assert_eq!(p.polarity, PresencePolarity::ActiveHigh);
                assert_eq!(p.pull, PresencePull::HashboardPullUp10kTo3v3);
                assert!(!p.source.pdf.is_empty());
            }
        }
    }

    /// The S17/S19-family rows must stay honestly partial: no PLUG pin, no
    /// presence fact, exactly the guide-stated pins. This is the axis' core
    /// refusal — extrapolating the S15 template would be fabrication.
    #[test]
    fn s17_s19_family_maps_stay_partial_and_presence_free() {
        for fam in [
            "s9k/s9se", "s17+", "t17e", "s19", "s19pro", "s19+", "s19jpro",
        ] {
            let c = io_connector_for(fam).expect(fam);
            assert!(!c.complete, "{fam}: must not claim completeness");
            assert!(
                c.presence.is_none(),
                "{fam}: PLUG polarity is not stated by its guide"
            );
            assert!(
                !c.pins.iter().any(|&(_, f)| f == PinFunction::PlugDetect),
                "{fam}: no guide states a PLUG pin"
            );
        }
        // S19j Pro additionally must not claim the contested TX pin 7.
        let s19jpro = io_connector_for("s19jpro").unwrap();
        assert!(
            !s19jpro
                .pins
                .iter()
                .any(|&(_, f)| matches!(f, PinFunction::Txd { .. })),
            "s19jpro: CI/TX pin is contested (its guide says pin 3, siblings say pin 7)"
        );
    }

    /// S9-era vs S15-era: same shell, different electrical map. This is the
    /// regression pin for the HARDWARE_REFERENCE.md:46 "universal
    /// compatibility" overclaim — the maps must NOT be equal.
    #[test]
    fn s9_era_and_s15_era_maps_differ_despite_same_shell() {
        let s9 = io_connector_for("s9").unwrap();
        let s15 = io_connector_for("s15").unwrap();
        assert_eq!(s9.mechanical, s15.mechanical, "same mechanical shell");
        let lookup = |pins: &[(u8, PinFunction)], want: PinFunction| {
            pins.iter().find(|&&(_, f)| f == want).map(|&(p, _)| p)
        };
        // TXD moved 11 → 7, RXD 12 → 8, RST 15 → 3, PLUG 5 → 13, SDA 3 → 15.
        assert_eq!(lookup(s9.pins, PinFunction::Txd { domain: 0 }), Some(11));
        assert_eq!(lookup(s15.pins, PinFunction::Txd { domain: 0 }), Some(7));
        assert_eq!(lookup(s9.pins, PinFunction::Rxd { domain: 0 }), Some(12));
        assert_eq!(lookup(s15.pins, PinFunction::Rxd { domain: 0 }), Some(8));
        assert_eq!(lookup(s9.pins, PinFunction::Rst { domain: 0 }), Some(15));
        assert_eq!(lookup(s15.pins, PinFunction::Rst { domain: 0 }), Some(3));
        assert_eq!(lookup(s9.pins, PinFunction::PlugDetect), Some(5));
        assert_eq!(lookup(s15.pins, PinFunction::PlugDetect), Some(13));
        assert_eq!(lookup(s9.pins, PinFunction::I2cSda), Some(3));
        assert_eq!(lookup(s15.pins, PinFunction::I2cSda), Some(15));
    }

    /// The stated plug-detect facts corroborate the HIGH=present decode every
    /// HAL path already uses (gpio.rs `data & mask != 0`, sysfs `1`,
    /// `read_gpio_value_active_high`): all corpus presence facts are
    /// ActiveHigh with the hashboard-side 10K pull-up.
    #[test]
    fn all_stated_presence_facts_are_active_high_hashboard_pullup() {
        let stated: Vec<_> = IO_CONNECTORS.iter().filter_map(|c| c.presence).collect();
        assert_eq!(stated.len(), 5, "S9, L3+, S11, T9+, S15 state PLUG0");
        for p in stated {
            assert_eq!(p.polarity, PresencePolarity::ActiveHigh);
            assert_eq!(p.pull, PresencePull::HashboardPullUp10kTo3v3);
        }
    }

    /// T9+ map: figure-resolved 7/8=TXD2/RXD2 and 21/22=RST1/RST2 (the same
    /// page's prose contradicts itself; the PCB render is authoritative).
    #[test]
    fn t9plus_contradiction_resolved_from_figure() {
        let t9 = io_connector_for("t9+").unwrap();
        assert!(t9.complete);
        assert_eq!(t9.pin_count, 24);
        let f = |pin: u8| t9.pins.iter().find(|&&(p, _)| p == pin).map(|&(_, f)| f);
        assert_eq!(f(7), Some(PinFunction::Txd { domain: 2 }));
        assert_eq!(f(8), Some(PinFunction::Rxd { domain: 2 }));
        assert_eq!(f(21), Some(PinFunction::Rst { domain: 1 }));
        assert_eq!(f(22), Some(PinFunction::Rst { domain: 2 }));
        // Three complete chain domains: TX/RX/RST triplets 0..=2 (RST2 shares
        // the reset group; the render shows RST0 at 15).
        for d in 0..=2u8 {
            assert!(t9
                .pins
                .iter()
                .any(|&(_, x)| x == PinFunction::Txd { domain: d }));
            assert!(t9
                .pins
                .iter()
                .any(|&(_, x)| x == PinFunction::Rxd { domain: d }));
            assert!(t9
                .pins
                .iter()
                .any(|&(_, x)| x == PinFunction::Rst { domain: d }));
        }
    }

    /// S11's address pins are EEPROM-address (AT24C02), not PIC-address.
    #[test]
    fn s11_addresses_an_eeprom_not_a_pic() {
        let s11 = io_connector_for("s11").unwrap();
        assert!(s11
            .pins
            .iter()
            .any(|&(p, f)| p == 6 && f == PinFunction::EepromAddrBit(2)));
        assert!(!s11
            .pins
            .iter()
            .any(|&(_, f)| matches!(f, PinFunction::PicAddrBit(_))));
    }

    /// Diode reference sheet: full 8-model coverage, cited, and the
    /// S17e/T17e rows differ from the plain S17/T17 rows (different board
    /// generation — the sheet distinguishes them on purpose).
    #[test]
    fn diode_reference_rows_are_cited_and_distinct_where_the_sheet_says_so() {
        assert_eq!(DIODE_REFERENCE.len(), 8);
        for r in DIODE_REFERENCE {
            assert_eq!(r.source.pdf, DIODE_REF_GUIDE.pdf);
            assert!(r.source.page >= 1 && r.source.page <= 3);
        }
        let s17 = diode_reference_for("s17").unwrap();
        let s17e = diode_reference_for("s17e").unwrap();
        assert_ne!(s17.diode, s17e.diode);
        let s19 = diode_reference_for("s19").unwrap();
        let s19pro = diode_reference_for("s19pro").unwrap();
        assert_eq!(
            s19.diode, s19pro.diode,
            "sheet states identical S19/S19 Pro rows"
        );
        assert!(
            diode_reference_for("s21").is_none(),
            "not in the sheet — refuse"
        );
    }

    /// The EN pin must never be representable as an actuatable enable: the
    /// only variant is name-only.
    #[test]
    fn s15_en_pin_is_name_only() {
        let s15 = io_connector_for("s15").unwrap();
        assert!(s15
            .pins
            .iter()
            .any(|&(p, f)| p == 2 && f == PinFunction::EnableNameOnly));
    }

    #[test]
    fn reseat_order_mentions_signal_cable_first() {
        assert!(SIGNAL_CABLE_RESEAT_ORDER.contains("signal cable FIRST"));
        assert!(SIGNAL_CABLE_RESEAT_ORDER.contains("U1/U2"));
    }
}
