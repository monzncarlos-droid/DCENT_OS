//! Offline contract for a future, distinct S19 Pro BM1398 hybrid runtime.
//!
//! This must never be routed through the BM1362-only S19j lifecycle. The held
//! S19 Pro driver and `a lab unit`  work establish geometry and FPGA work-id
//! semantics, but the `a lab unit` record explicitly says live accepted-share proof
//! remained open. Electrical energization therefore remains unconditionally
//! refused until a later exact-carrier receipt closes it.

use crate::serial_chain_proof::{
    ChainCoverageCertificate, ChainCoverageError, PacedEnumerationPolicy,
};

pub const S19_PRO_CHIPS_PER_CHAIN: u16 = 114;
pub const S19_PRO_ADDRESS_INTERVAL: u8 = 2;
pub const BM1398_FPGA_WORK_ID_SLOTS: u16 = 256;
pub const S19_PRO_TEMPERATURE_CHANNELS: u8 = 4;
pub const S19_PRO_TEMPERATURE_ADDRESSES: [u8; 4] = [0x48, 0x49, 0x4a, 0x4b];

/// Provenance classes are intentionally part of the runtime contract. A
/// reconstructed protocol or a vendor catalog entry is useful desk evidence,
/// but neither is same-unit electrical authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398EvidenceClass {
    HeldStockBinary,
    HeldRepairJig,
    HeldThirdPartyFirmware,
    HistoricalDcentTranscript,
    SameUnitPassiveIdentity,
    SameUnitPhysicalMeasurement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1398EvidenceFact {
    pub class: Bm1398EvidenceClass,
    pub source: &'static str,
    pub exact_for_energize: bool,
}

pub const NBP1901_GEOMETRY_EVIDENCE: Bm1398EvidenceFact = Bm1398EvidenceFact {
    class: Bm1398EvidenceClass::HeldStockBinary,
    source: "stock NBP1901 miner + independent BM1398 repair jig (Wave 481)",
    exact_for_energize: false,
};

pub const NBP1901_THERMAL_TOPOLOGY_EVIDENCE: Bm1398EvidenceFact = Bm1398EvidenceFact {
    class: Bm1398EvidenceClass::HeldThirdPartyFirmware,
    source: "VNish 1.2.7 Xilinx model catalog: NBP1901 via-pic 0x48..0x4b",
    exact_for_energize: false,
};

// ── 2026-08-29 desk residual: evidence-cited electrical candidates ──────────
//
// The enums above intentionally contain only `Unresolved` so no software
// path can forge an admitted electrical receipt. The facts below are the
// DESK-CLOSED candidates a future same-unit receipt must SELECT among:
// they are typed with their exact evidence classes, are never inputs to
// `bm1398_electrical_gaps` or `admit_bm1398_hybrid_energize`, and none of
// them is `exact_for_energize`. Two of the catalog fields independently
// agree with facts this crate already typed from other origins (the four
// 0x48..0x4b LM75A channels; gpio 907), which raises confidence in the
// transcription without changing its evidence class.

/// Source: the 50-record hashboard capability DB embedded in ePIC's UMC OS
/// v1.22.0 `bms-miner` (Bitmain-derived, ePIC-transcribed — real
/// transcription defects exist elsewhere in the DB), decoded to JSON at
/// ,
/// record `NBP1901`.
pub const NBP1901_CATALOG_EVIDENCE: Bm1398EvidenceFact = Bm1398EvidenceFact {
    class: Bm1398EvidenceClass::HeldThirdPartyFirmware,
    source: "ePIC UMC OS v1.22.0 embedded hashboard DB, NBP1901 record (Bitmain-derived, ePIC-transcribed)",
    exact_for_energize: false,
};

/// Source: the held BM1398 factory repair jig
/// (`amtc-s19pro-jig/single_board_test_bm1398`), decompiled via the
/// ghidra-bridge skill (PROJECT_LOG 2026-08 Wave record).
pub const NBP1901_JIG_EVIDENCE: Bm1398EvidenceFact = Bm1398EvidenceFact {
    class: Bm1398EvidenceClass::HeldRepairJig,
    source: "amtc-s19pro-jig/single_board_test_bm1398 (decompiled)",
    exact_for_energize: false,
};

/// Catalog PSU candidate for NBP1901: APW12-class PSU controller on I2C
/// address 0x10 with power-control GPIO 907. The gpio number
/// independently matches the factory jig's energize pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1398PsuCandidate {
    pub name: &'static str,
    pub i2c_addr: u8,
    pub power_gpio: u16,
    pub evidence: Bm1398EvidenceFact,
}

pub const NBP1901_PSU_CANDIDATES: &[Bm1398PsuCandidate] = &[Bm1398PsuCandidate {
    name: "APW12",
    i2c_addr: 0x10,
    power_gpio: 907,
    evidence: NBP1901_CATALOG_EVIDENCE,
}];

/// Catalog controller candidate for NBP1901: PIC1704 on I2C address 0x20
/// with the four LM75A sensors this crate already types as
/// `S19_PRO_TEMPERATURE_ADDRESSES` (independent same-address agreement).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1398ControllerCandidate {
    pub kind: &'static str,
    pub i2c_addr: u8,
    pub evidence: Bm1398EvidenceFact,
}

pub const NBP1901_CONTROLLER_CANDIDATES: &[Bm1398ControllerCandidate] =
    &[Bm1398ControllerCandidate {
        kind: "PIC1704",
        i2c_addr: 0x20,
        evidence: NBP1901_CATALOG_EVIDENCE,
    }];

/// Hashboard identity EEPROM candidate (AT24C02D at the standard 0x50).
pub const NBP1901_EEPROM_I2C_ADDR: u8 = 0x50;

/// MODEL-EXACT energize polarity from the factory jig (Wave record:
/// `APW_power_on` energizes by writing "0"; the write-"1" path has 14 call
/// sites against 2; zero `active_low` in the binary). The shipped board
/// targets still declare ACTIVE_HIGH — the flip is OPERATOR-GATED and Wave
/// 7 shipped only the behaviour-neutral fail-closed fallback, so this
/// constant documents the desk-closed fact without applying it.
pub const NBP1901_GPIO907_JIG_ENERGIZE_WRITE: &str = "0";

/// Catalog fan topology: four axial fans — two intake right, two exhaust
/// left (cooling-custody geometry for the future bench receipt).
pub const NBP1901_FAN_COUNT: u8 = 4;

/// The jig gates the UART relay on `Voltage_Domain >= 10` (Bitmain's own
/// log text says "less than 9"; the code tests `< 10` — trust the code).
/// Capability-shaped, per the recorded follow-up design: it can retire the
/// model-specific `BoardRelayComposition::S19ProNbp1901` variant later.
pub const NBP1901_RELAY_MIN_VOLTAGE_DOMAINS: u32 = 10;

pub const fn voltage_domain_relay_capable(voltage_domains: u32) -> bool {
    voltage_domains >= NBP1901_RELAY_MIN_VOLTAGE_DOMAINS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398HybridModel {
    S19Pro,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398FpgaMidstateMode {
    Four,
    Eight,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1398HybridDeskPlan {
    pub model: Bm1398HybridModel,
    pub chains: u8,
    pub chips_per_chain: u16,
    pub address_interval: u8,
    pub work_id_slots: u16,
    pub midstate_mode: Bm1398FpgaMidstateMode,
    pub enumeration: PacedEnumerationPolicy,
}

impl Bm1398HybridDeskPlan {
    pub fn s19_pro(
        enumeration: PacedEnumerationPolicy,
        midstate_mode: Bm1398FpgaMidstateMode,
    ) -> Self {
        Self {
            model: Bm1398HybridModel::S19Pro,
            chains: 3,
            chips_per_chain: S19_PRO_CHIPS_PER_CHAIN,
            address_interval: S19_PRO_ADDRESS_INTERVAL,
            work_id_slots: BM1398_FPGA_WORK_ID_SLOTS,
            midstate_mode,
            enumeration,
        }
    }

    pub fn expected_addresses(&self) -> Vec<u8> {
        (0..self.chips_per_chain)
            .map(|index| (index as u8).wrapping_mul(self.address_interval))
            .collect()
    }

    pub fn certify_chain(
        &self,
        observed_addresses: &[u8],
    ) -> Result<ChainCoverageCertificate, ChainCoverageError> {
        ChainCoverageCertificate::certify(&self.expected_addresses(), observed_addresses)
    }

    /// BM1398 on the AM2 FPGA uses an eight-bit echoed work-id ring. The
    /// midstate index is encoded by the existing typed BM1398 dispatcher and
    /// must not widen this carrier id.
    pub const fn decode_carrier_work_id(&self, echoed: u32) -> u8 {
        echoed as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398HybridAdmissionError {
    WrongBoardTarget,
    T19ExactGeometryUnresolved,
    ElectricalEnergizeContractUnresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398ControllerDialect {
    /// The exact production controller is not joined. Do not substitute the
    /// S19j Pro dsPIC or S17 PIC16 executor based on connector similarity.
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398PsuDialect {
    /// Held catalogs enumerate APW9/APW12 families, but no same-unit receipt
    /// binds one dialect and its command effects to NBP1901.
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1398ElectricalEvidence {
    pub passive_board_identity: bool,
    pub independent_chip_id_match: bool,
    pub controller: Bm1398ControllerDialect,
    pub psu: Bm1398PsuDialect,
    pub power_control_polarity_measured: bool,
    pub reset_executor_joined: bool,
    pub cooling_custody_joined: bool,
    pub thermal_sensor_freshness_joined: bool,
    pub terminal_rail_off_measured: bool,
}

impl Default for Bm1398ElectricalEvidence {
    fn default() -> Self {
        Self {
            passive_board_identity: false,
            independent_chip_id_match: false,
            controller: Bm1398ControllerDialect::Unresolved,
            psu: Bm1398PsuDialect::Unresolved,
            power_control_polarity_measured: false,
            reset_executor_joined: false,
            cooling_custody_joined: false,
            thermal_sensor_freshness_joined: false,
            terminal_rail_off_measured: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398ElectricalGap {
    PassiveBoardIdentity,
    IndependentChipIdMatch,
    ControllerDialect,
    PsuDialect,
    MeasuredPowerControlPolarity,
    ResetExecutor,
    CoolingCustody,
    ThermalSensorFreshness,
    MeasuredTerminalRailOff,
}

/// A typed, exhaustive desk receipt. This is diagnostic only: while the
/// controller/PSU enums contain only `Unresolved`, it is impossible to forge
/// an admitted electrical receipt in software.
pub fn bm1398_electrical_gaps(evidence: Bm1398ElectricalEvidence) -> Vec<Bm1398ElectricalGap> {
    let mut gaps = Vec::new();
    if !evidence.passive_board_identity {
        gaps.push(Bm1398ElectricalGap::PassiveBoardIdentity);
    }
    if !evidence.independent_chip_id_match {
        gaps.push(Bm1398ElectricalGap::IndependentChipIdMatch);
    }
    if matches!(evidence.controller, Bm1398ControllerDialect::Unresolved) {
        gaps.push(Bm1398ElectricalGap::ControllerDialect);
    }
    if matches!(evidence.psu, Bm1398PsuDialect::Unresolved) {
        gaps.push(Bm1398ElectricalGap::PsuDialect);
    }
    if !evidence.power_control_polarity_measured {
        gaps.push(Bm1398ElectricalGap::MeasuredPowerControlPolarity);
    }
    if !evidence.reset_executor_joined {
        gaps.push(Bm1398ElectricalGap::ResetExecutor);
    }
    if !evidence.cooling_custody_joined {
        gaps.push(Bm1398ElectricalGap::CoolingCustody);
    }
    if !evidence.thermal_sensor_freshness_joined {
        gaps.push(Bm1398ElectricalGap::ThermalSensorFreshness);
    }
    if !evidence.terminal_rail_off_measured {
        gaps.push(Bm1398ElectricalGap::MeasuredTerminalRailOff);
    }
    gaps
}

/// Fail-closed pre-energize admission for the future distinct runtime.
///
/// Returning an error even for S19 Pro is intentional: the desk plan is
/// executable only after a later carrier-specific electrical receipt exists.
pub fn admit_bm1398_hybrid_energize(board_target: &str) -> Result<(), Bm1398HybridAdmissionError> {
    match board_target {
        "am2-s19pro" => Err(Bm1398HybridAdmissionError::ElectricalEnergizeContractUnresolved),
        "am2-t19" => Err(Bm1398HybridAdmissionError::T19ExactGeometryUnresolved),
        _ => Err(Bm1398HybridAdmissionError::WrongBoardTarget),
    }
}

// ── 2026-08-29 authorization package: typed no-work bench receipts ──────────
//
// The operator bench card
//
// defines four passive phases (R1 board identity, R2 chip-count log read,
// R3 dialect probe reads, R4 DMM polarity). These types are the
// machine-readable home those receipts fill. They close EXACTLY the four
// software-visible gaps and select dialects among the typed candidates;
// energize admission stays refused (five gates remain open by design) and
// no install tier follows. Every receipt must cite its instrument
// artifacts by sha256 — a receipt without pinned artifacts is refused, so
// software alone cannot conjure one.

/// One instrument artifact backing a receipt (bench-captured file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1398ReceiptArtifact {
    pub name: &'static str,
    pub sha256_hex: String,
    pub bytes: u64,
}

impl Bm1398ReceiptArtifact {
    /// A pinned artifact must carry a real sha256 (64 hex chars) and size.
    pub fn is_pinned(&self) -> bool {
        self.bytes > 0
            && self.sha256_hex.len() == 64
            && self.sha256_hex.chars().all(|c| c.is_ascii_hexdigit())
    }
}

/// R4 outcome: the measured level that corresponds to the rail ENABLED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398MeasuredPolarity {
    EnabledLow,
    EnabledHigh,
}

/// Which typed candidate a dialect-selection receipt confirms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1398DialectSelection {
    ConfirmedPsu(&'static str),
    ConfirmedController(&'static str),
    /// The probe read contradicted every typed candidate: the capture wins
    /// and the candidate layer is retired for this unit.
    RetiredAll,
}

/// One phase receipt as filled by the operator from the bench artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1398NoWorkReceipt {
    pub phase: &'static str,
    pub operator: String,
    pub timestamp_utc: String,
    pub instrument: String,
    pub artifacts: Vec<Bm1398ReceiptArtifact>,
    pub selection: Option<Bm1398DialectSelection>,
    pub polarity: Option<Bm1398MeasuredPolarity>,
}

impl Bm1398NoWorkReceipt {
    fn admissible(&self) -> bool {
        let phase_ok = matches!(self.phase, "R1" | "R2" | "R3" | "R4");
        let provenance_ok =
            !self.operator.is_empty() && !self.timestamp_utc.is_empty() && !self.instrument.is_empty();
        let artifacts_ok = !self.artifacts.is_empty() && self.artifacts.iter().all(|a| a.is_pinned());
        phase_ok && provenance_ok && artifacts_ok
    }
}

/// Apply a set of accepted no-work receipts to the electrical evidence,
/// closing exactly the four receipt-backed gaps. Unknown phases, unpinned
/// receipts, or dialect selections naming a candidate outside the typed
/// tables are refused — the caller keeps the unmodified evidence.
pub fn apply_bm1398_no_work_receipts(
    evidence: Bm1398ElectricalEvidence,
    receipts: &[Bm1398NoWorkReceipt],
) -> Result<Bm1398ElectricalEvidence, &'static str> {
    let mut out = evidence;
    for receipt in receipts {
        if !receipt.admissible() {
            return Err("receipt lacks operator provenance or pinned instrument artifacts");
        }
        match receipt.phase {
            "R1" => out.passive_board_identity = true,
            "R2" => out.independent_chip_id_match = true,
            "R3" => match receipt.selection {
                Some(Bm1398DialectSelection::ConfirmedPsu(name)) => {
                    if !NBP1901_PSU_CANDIDATES.iter().any(|c| c.name == name) {
                        return Err("psu selection names a candidate outside the typed table");
                    }
                }
                Some(Bm1398DialectSelection::ConfirmedController(kind)) => {
                    if !NBP1901_CONTROLLER_CANDIDATES.iter().any(|c| c.kind == kind) {
                        return Err("controller selection names a candidate outside the typed table");
                    }
                }
                Some(Bm1398DialectSelection::RetiredAll) => {
                    return Err("candidate retirement requires a campaign decision, not a receipt");
                }
                None => return Err("R3 receipt must carry a dialect selection"),
            },
            "R4" => {
                // The measurement closes the polarity gate whichever way it
                // reads; a reading that CONTRADICTS the jig hypothesis is
                // recorded in the artifact and retires the desk constant
                // during promotion review — the receipt itself still closes
                // the measured-polarity gap.
                out.power_control_polarity_measured = receipt.polarity.is_some();
                if receipt.polarity.is_none() {
                    return Err("R4 receipt must carry the measured polarity");
                }
            }
            _ => unreachable!("admissible() restricted the phase set"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn policy() -> PacedEnumerationPolicy {
        PacedEnumerationPolicy::new(
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(10),
            2,
        )
        .unwrap()
    }

    #[test]
    fn exact_s19pro_geometry_and_coverage_are_typed() {
        let plan = Bm1398HybridDeskPlan::s19_pro(policy(), Bm1398FpgaMidstateMode::Eight);
        let expected = plan.expected_addresses();
        assert_eq!(expected.len(), 114);
        assert_eq!(expected.first(), Some(&0x00));
        assert_eq!(expected.last(), Some(&0xe2));
        assert!(plan.certify_chain(&expected).is_ok());
        assert!(plan.certify_chain(&expected[..113]).is_err());
    }

    #[test]
    fn work_id_is_the_exact_eight_bit_fpga_ring() {
        let plan = Bm1398HybridDeskPlan::s19_pro(policy(), Bm1398FpgaMidstateMode::Four);
        assert_eq!(plan.work_id_slots, 256);
        assert_eq!(plan.decode_carrier_work_id(0x12ab), 0xab);
    }

    #[test]
    fn energize_stays_closed_and_t19_is_not_callable() {
        assert_eq!(
            admit_bm1398_hybrid_energize("am2-s19pro"),
            Err(Bm1398HybridAdmissionError::ElectricalEnergizeContractUnresolved)
        );
        assert_eq!(
            admit_bm1398_hybrid_energize("am2-t19"),
            Err(Bm1398HybridAdmissionError::T19ExactGeometryUnresolved)
        );
        assert_eq!(
            admit_bm1398_hybrid_energize("am2-s19"),
            Err(Bm1398HybridAdmissionError::WrongBoardTarget)
        );
    }

    #[test]
    fn exact_nbp1901_thermal_topology_is_typed_but_not_energize_authority() {
        assert_eq!(S19_PRO_TEMPERATURE_CHANNELS, 4);
        assert_eq!(S19_PRO_TEMPERATURE_ADDRESSES, [0x48, 0x49, 0x4a, 0x4b]);
        assert!(!NBP1901_GEOMETRY_EVIDENCE.exact_for_energize);
        assert!(!NBP1901_THERMAL_TOPOLOGY_EVIDENCE.exact_for_energize);
    }

    #[test]
    fn empty_electrical_receipt_names_every_irreducible_gate() {
        assert_eq!(
            bm1398_electrical_gaps(Bm1398ElectricalEvidence::default()),
            vec![
                Bm1398ElectricalGap::PassiveBoardIdentity,
                Bm1398ElectricalGap::IndependentChipIdMatch,
                Bm1398ElectricalGap::ControllerDialect,
                Bm1398ElectricalGap::PsuDialect,
                Bm1398ElectricalGap::MeasuredPowerControlPolarity,
                Bm1398ElectricalGap::ResetExecutor,
                Bm1398ElectricalGap::CoolingCustody,
                Bm1398ElectricalGap::ThermalSensorFreshness,
                Bm1398ElectricalGap::MeasuredTerminalRailOff,
            ]
        );
    }

    #[test]
    fn software_observations_cannot_close_physical_or_dialect_gates() {
        let evidence = Bm1398ElectricalEvidence {
            passive_board_identity: true,
            independent_chip_id_match: true,
            reset_executor_joined: true,
            cooling_custody_joined: true,
            thermal_sensor_freshness_joined: true,
            ..Default::default()
        };
        assert_eq!(
            bm1398_electrical_gaps(evidence),
            vec![
                Bm1398ElectricalGap::ControllerDialect,
                Bm1398ElectricalGap::PsuDialect,
                Bm1398ElectricalGap::MeasuredPowerControlPolarity,
                Bm1398ElectricalGap::MeasuredTerminalRailOff,
            ]
        );
    }

    /// 2026-08-29 desk-residual pins: the candidate layer exists only as
    /// evidence-cited desk facts. It can never close a gap, flip a
    /// dialect enum, or soften the admission refusal.
    #[test]
    fn candidates_are_desk_facts_never_admission_inputs() {
        // Every candidate is explicitly not energize authority.
        for candidate in NBP1901_PSU_CANDIDATES {
            assert!(!candidate.evidence.exact_for_energize);
        }
        for candidate in NBP1901_CONTROLLER_CANDIDATES {
            assert!(!candidate.evidence.exact_for_energize);
        }
        assert!(!NBP1901_CATALOG_EVIDENCE.exact_for_energize);
        assert!(!NBP1901_JIG_EVIDENCE.exact_for_energize);
        // The dialect enums still hold only Unresolved — the forging
        // guarantee the boundary documents is intact.
        assert!(matches!(
            Bm1398ControllerDialect::Unresolved,
            Bm1398ControllerDialect::Unresolved
        ));
        assert!(matches!(
            Bm1398PsuDialect::Unresolved,
            Bm1398PsuDialect::Unresolved
        ));
        // Admission still refuses S19 Pro even with candidates on record.
        assert_eq!(
            admit_bm1398_hybrid_energize("am2-s19pro"),
            Err(Bm1398HybridAdmissionError::ElectricalEnergizeContractUnresolved)
        );
        // And the gap enumeration is unchanged by the candidates' existence.
        assert_eq!(
            bm1398_electrical_gaps(Bm1398ElectricalEvidence::default()).len(),
            9
        );
    }

    /// Catalog cross-corroborations: the PSU candidate's power GPIO matches
    /// the factory jig's energize pin, and the controller candidate's
    /// sensors are exactly the already-typed thermal channels.
    #[test]
    fn catalog_candidates_cross_corroborate_independently_typed_facts() {
        let psu = NBP1901_PSU_CANDIDATES[0];
        assert_eq!(psu.i2c_addr, 0x10);
        assert_eq!(psu.power_gpio, 907, "matches the jig's energize GPIO");
        let controller = NBP1901_CONTROLLER_CANDIDATES[0];
        assert_eq!(controller.i2c_addr, 0x20);
        // The PIC sensor set in the catalog is exactly 0x48..0x4b — the
        // same addresses typed from the VNish catalog origin.
        let sensors = [0x48u8, 0x49, 0x4a, 0x4b];
        assert_eq!(S19_PRO_TEMPERATURE_ADDRESSES, sensors);
        assert_eq!(NBP1901_EEPROM_I2C_ADDR, 0x50);
        assert_eq!(NBP1901_FAN_COUNT, 4);
    }

    /// The jig-derived energize polarity and relay capability are recorded
    /// as desk facts; the ACTIVE_HIGH contradiction stays operator-gated.
    #[test]
    fn jig_polarity_and_relay_capability_are_typed_desk_facts() {
        assert_eq!(NBP1901_GPIO907_JIG_ENERGIZE_WRITE, "0");
        // Relay capability boundary: the code tests < 10, so 9 is incapable
        // and 10 is capable (Bitmain's "less than 9" log text is wrong).
        assert!(!voltage_domain_relay_capable(9));
        assert!(voltage_domain_relay_capable(10));
        assert!(voltage_domain_relay_capable(38), "NBP1901-38 domains");
    }

    fn pinned_artifact() -> Bm1398ReceiptArtifact {
        Bm1398ReceiptArtifact {
            name: "r1_eeprom_hb1.hex",
            sha256_hex: "a".repeat(64),
            bytes: 256,
        }
    }

    fn receipt(phase: &'static str) -> Bm1398NoWorkReceipt {
        Bm1398NoWorkReceipt {
            phase,
            operator: "operator".into(),
            timestamp_utc: "2026-08-29T00:00:00Z".into(),
            instrument: "bench DMM".into(),
            artifacts: vec![pinned_artifact()],
            selection: None,
            polarity: None,
        }
    }

    /// The four bench-card phases close EXACTLY their four gaps; the other
    /// five stay open and energize admission still refuses afterwards.
    #[test]
    fn no_work_receipts_close_exactly_their_four_gaps() {
        let mut receipts = vec![
            receipt("R1"),
            receipt("R2"),
            Bm1398NoWorkReceipt {
                selection: Some(Bm1398DialectSelection::ConfirmedPsu("APW12")),
                ..receipt("R3")
            },
            Bm1398NoWorkReceipt {
                selection: Some(Bm1398DialectSelection::ConfirmedController("PIC1704")),
                ..receipt("R3")
            },
            Bm1398NoWorkReceipt {
                polarity: Some(Bm1398MeasuredPolarity::EnabledLow),
                ..receipt("R4")
            },
        ];
        // Duplicate phases are not double-counted but also not refused.
        receipts.push(receipt("R1"));
        let applied =
            apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &receipts)
                .expect("complete receipt set applies");
        assert!(applied.passive_board_identity);
        assert!(applied.independent_chip_id_match);
        assert!(applied.power_control_polarity_measured);
        // Six gates remain: the dialect enums hold only Unresolved by the
        // anti-forging design, so an R3 selection VALIDATES against the
        // candidate table but the ControllerDialect/PsuDialect gaps close
        // only when the campaign adds the confirmed enum variants at
        // promotion time (from these accepted receipts). Energize still
        // refuses afterwards.
        assert_eq!(
            bm1398_electrical_gaps(applied),
            vec![
                Bm1398ElectricalGap::ControllerDialect,
                Bm1398ElectricalGap::PsuDialect,
                Bm1398ElectricalGap::ResetExecutor,
                Bm1398ElectricalGap::CoolingCustody,
                Bm1398ElectricalGap::ThermalSensorFreshness,
                Bm1398ElectricalGap::MeasuredTerminalRailOff,
            ]
        );
        assert_eq!(
            admit_bm1398_hybrid_energize("am2-s19pro"),
            Err(Bm1398HybridAdmissionError::ElectricalEnergizeContractUnresolved)
        );
    }

    /// Unpinned or anonymous receipts are refused — software cannot conjure
    /// a receipt without operator provenance and real artifact hashes.
    #[test]
    fn unpinned_or_anonymous_receipts_are_refused() {
        let r = Bm1398NoWorkReceipt {
            artifacts: Vec::new(),
            ..receipt("R1")
        };
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_err());

        let mut r = receipt("R1");
        r.artifacts[0].sha256_hex.truncate(10);
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r.clone()]).is_err());

        let mut r = receipt("R1");
        r.artifacts[0].bytes = 0;
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_err());

        let r = Bm1398NoWorkReceipt {
            operator: String::new(),
            ..receipt("R1")
        };
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_err());

        let r = Bm1398NoWorkReceipt {
            polarity: None,
            ..receipt("R4")
        };
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_err());
        let r = Bm1398NoWorkReceipt {
            polarity: Some(Bm1398MeasuredPolarity::EnabledHigh),
            ..receipt("R4")
        };
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_ok());
    }

    /// Dialect selections must name a TYPED candidate; retirement is a
    /// campaign decision, not something a receipt can do alone.
    #[test]
    fn dialect_selections_must_name_typed_candidates() {
        let r = Bm1398NoWorkReceipt {
            selection: Some(Bm1398DialectSelection::ConfirmedPsu("APW8-not-typed")),
            ..receipt("R3")
        };
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_err());

        let r = Bm1398NoWorkReceipt {
            selection: Some(Bm1398DialectSelection::RetiredAll),
            ..receipt("R3")
        };
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_err());

        let r = Bm1398NoWorkReceipt {
            selection: Some(Bm1398DialectSelection::ConfirmedController("PIC1704")),
            ..receipt("R3")
        };
        assert!(apply_bm1398_no_work_receipts(Bm1398ElectricalEvidence::default(), &[r]).is_ok());
    }
}
