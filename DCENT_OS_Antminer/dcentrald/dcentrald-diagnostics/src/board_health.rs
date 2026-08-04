//! Per-board health result and current runtime-snapshot grading.
//!
//! The active two-minute board test remains a target producer. The current API
//! builds fail-closed triage snapshots and does not claim these operations ran:
//!   1. Chip enumeration (verify count matches expected)
//!   2. Voltage domain verification (PIC set/get readback)
//!   3. CRC error rate test (100 dummy commands, count errors)
//!   4. Temperature distribution (check for thermal hotspots)
//!   5. EEPROM validation (if present)

use serde::{Deserialize, Serialize};

use crate::evidence::{required_board_evidence_gaps, DiagnosticEvidence};

/// Trust classification for BoardHealth producer-supplied context.
///
/// These strings help an operator interpret a report, but they are not typed
/// observations and never participate in grading. There is intentionally no
/// `Verified` variant: promotion requires replacing each claim with typed
/// evidence, not relabelling free-form prose.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProducerContextTrust {
    #[default]
    Unverified,
}

/// Board health test configuration.
pub struct BoardHealthTest {
    /// Target chain ID (6, 7, or 8 on S9).
    pub chain_id: u8,
}

impl BoardHealthTest {
    pub fn new(chain_id: u8) -> Self {
        Self { chain_id }
    }
}

/// Board health test result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardHealthResult {
    /// Chain ID tested.
    pub chain_id: u8,

    /// Where the data came from.
    #[serde(default)]
    pub data_source: String,

    /// Whether this is a point-in-time snapshot or a dedicated test run.
    #[serde(default)]
    pub measurement_type: String,

    /// Current runtime status string for the chain.
    #[serde(default)]
    pub status: String,

    /// Current estimated runtime hashrate for the chain.
    #[serde(default)]
    pub estimated_hashrate_ghs: f64,

    /// Operator-facing notes about inferred or unavailable fields.
    #[serde(default)]
    pub notes: Vec<String>,

    /// Explicit trust label for `data_source`, `measurement_type`, `status`,
    /// `estimated_hashrate_ghs`, and `notes`. These fields are producer prose,
    /// not grade-bearing evidence.
    #[serde(default)]
    pub producer_context_trust: ProducerContextTrust,

    /// Chip enumeration results.
    pub chips_expected: u8,
    pub chips_responding: u8,
    pub dead_chip_addresses: Vec<u8>,
    /// Provenance for the responding-chip enumeration used by grading.
    /// A saved profile or an unqualified runtime summary is not a bounded
    /// enumeration test and therefore cannot support a passing verdict.
    #[serde(default)]
    pub chip_count_evidence: DiagnosticEvidence<u8>,

    /// Voltage domain verification.
    pub voltage_setpoint_v: f32,
    pub voltage_readback_v: f32,
    pub voltage_deviation_pct: f32,
    pub voltage_ok: bool,
    /// Provenance for the voltage value used by grading. Legacy payloads
    /// deserialize as Unavailable and therefore cannot retain an A/B verdict.
    #[serde(default)]
    pub voltage_evidence: DiagnosticEvidence<f32>,

    /// CRC error rate test.
    pub crc_commands_sent: u32,
    pub crc_errors_received: u32,
    pub crc_error_rate_pct: f32,
    pub crc_ok: bool,
    /// Provenance for the positive bounded command count.
    #[serde(default)]
    pub crc_window_evidence: DiagnosticEvidence<u32>,
    /// Provenance for the CRC verdict/counter window.
    #[serde(default)]
    pub crc_evidence: DiagnosticEvidence<u32>,

    /// Temperature readings.
    pub temperature_c: f32,
    pub temperature_ok: bool,
    /// Provenance for the temperature observation used by grading.
    #[serde(default)]
    pub temperature_evidence: DiagnosticEvidence<f32>,

    /// EEPROM data (if available).
    pub eeprom_present: bool,
    pub eeprom_valid: bool,
    pub eeprom_model: Option<String>,
    pub eeprom_serial: Option<String>,
    /// Validated observation that EEPROM is present or absent for this board.
    #[serde(default)]
    pub eeprom_presence_evidence: DiagnosticEvidence<bool>,
    /// Provenance for EEPROM validity. Model metadata is Inferred, not a
    /// checksum/schema validation.
    #[serde(default)]
    pub eeprom_evidence: DiagnosticEvidence<bool>,

    /// True only when every evidence item required for a passing grade was
    /// directly measured.
    #[serde(default, skip_deserializing)]
    pub required_evidence_measured: bool,

    /// Overall board health grade.
    pub grade: char,
    pub grade_explanation: String,
}

impl BoardHealthResult {
    /// Calculate the overall board grade from individual test results.
    pub fn calculate_grade(&mut self) {
        let assessment = assess_board_health(
            self.chips_expected,
            self.chips_responding,
            self.dead_chip_addresses.len(),
            self.voltage_setpoint_v,
            self.voltage_readback_v,
            self.crc_commands_sent,
            self.crc_errors_received,
            self.temperature_c,
            self.eeprom_present,
            self.eeprom_valid,
        );
        self.voltage_deviation_pct = assessment.voltage_deviation_pct;
        self.voltage_ok = assessment.voltage_ok;
        self.crc_error_rate_pct = assessment.crc_error_rate_pct;
        self.crc_ok = assessment.crc_ok;
        self.temperature_ok = assessment.temperature_ok;

        let evidence_gaps = required_board_evidence_gaps(
            self.chips_responding,
            &self.chip_count_evidence,
            self.temperature_c,
            &self.temperature_evidence,
            self.voltage_readback_v,
            &self.voltage_evidence,
            self.crc_commands_sent,
            &self.crc_window_evidence,
            self.crc_errors_received,
            &self.crc_evidence,
            self.eeprom_present,
            &self.eeprom_presence_evidence,
            self.eeprom_valid,
            &self.eeprom_evidence,
        );
        self.required_evidence_measured = evidence_gaps.is_empty();

        // A/B are passing manufacturing/repair verdicts. They require direct
        // evidence; commanded, inferred or unavailable values cap the result
        // at C without hiding any worse health-derived grade.
        self.grade = if !self.required_evidence_measured && matches!(assessment.grade, 'A' | 'B') {
            'C'
        } else {
            assessment.grade
        };

        self.grade_explanation = format!(
            "{} chips responding/{} expected, {} dead, {} issues{}",
            self.chips_responding,
            self.chips_expected,
            assessment.dead_chips,
            assessment.issue_count,
            if evidence_gaps.is_empty() {
                String::new()
            } else {
                format!(
                    "; passing grade withheld: {}",
                    evidence_gaps
                        .iter()
                        .map(|gap| format!("{gap} evidence not measured"))
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            }
        );
    }
}

pub(crate) const MIN_BOARD_VOLTAGE_V: f32 = 5.0;
pub(crate) const MAX_BOARD_VOLTAGE_V: f32 = 25.0;
pub(crate) const MAX_VOLTAGE_DEVIATION_PCT: f32 = 5.0;
pub(crate) const MIN_BOARD_TEMPERATURE_C: f32 = -40.0;
pub(crate) const MAX_BOARD_TEMPERATURE_C: f32 = 75.0;
pub(crate) const CRITICAL_BOARD_TEMPERATURE_C: f32 = 100.0;
pub(crate) const CRITICAL_CRC_ERROR_RATE_PCT: f32 = 10.0;

pub(crate) struct BoardHealthAssessment {
    pub voltage_deviation_pct: f32,
    pub crc_error_rate_pct: f32,
    pub voltage_ok: bool,
    pub crc_ok: bool,
    pub temperature_ok: bool,
    pub dead_chips: usize,
    pub issue_count: usize,
    pub grade: char,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn assess_board_health(
    chips_expected: u8,
    chips_responding: u8,
    reported_dead_chips: usize,
    voltage_setpoint_v: f32,
    voltage_readback_v: f32,
    crc_commands_sent: u32,
    crc_errors_received: u32,
    temperature_c: f32,
    eeprom_present: bool,
    eeprom_valid: bool,
) -> BoardHealthAssessment {
    let topology_valid = chips_expected > 0 && chips_responding <= chips_expected;
    let missing_chips = if topology_valid {
        chips_expected.saturating_sub(chips_responding) as usize
    } else {
        chips_expected.max(chips_responding) as usize
    };
    let dead_chips = missing_chips.max(reported_dead_chips);

    let voltage_values_plausible = voltage_setpoint_v.is_finite()
        && voltage_readback_v.is_finite()
        && (MIN_BOARD_VOLTAGE_V..=MAX_BOARD_VOLTAGE_V).contains(&voltage_setpoint_v)
        && (MIN_BOARD_VOLTAGE_V..=MAX_BOARD_VOLTAGE_V).contains(&voltage_readback_v);
    let voltage_deviation_pct = if voltage_values_plausible {
        ((voltage_readback_v - voltage_setpoint_v).abs() / voltage_setpoint_v) * 100.0
    } else {
        100.0
    };
    let voltage_ok = voltage_values_plausible && voltage_deviation_pct <= MAX_VOLTAGE_DEVIATION_PCT;

    let crc_error_rate_pct = if crc_commands_sent > 0 {
        (crc_errors_received as f64 * 100.0 / crc_commands_sent as f64) as f32
    } else if crc_errors_received > 0 {
        100.0
    } else {
        0.0
    };
    let crc_ok = crc_commands_sent > 0 && crc_errors_received == 0;
    let temperature_ok = temperature_c.is_finite()
        && (MIN_BOARD_TEMPERATURE_C..MAX_BOARD_TEMPERATURE_C).contains(&temperature_c);
    let eeprom_ok = !eeprom_present || eeprom_valid;

    let issue_count = [
        !voltage_ok,
        !crc_ok,
        !temperature_ok,
        missing_chips > 0,
        !eeprom_ok,
    ]
    .into_iter()
    .filter(|issue| *issue)
    .count();

    let mut grade = if !topology_valid {
        'F'
    } else if issue_count == 0 && dead_chips == 0 {
        'A'
    } else if issue_count <= 1 && dead_chips <= 2 {
        'B'
    } else if issue_count <= 2 && dead_chips <= 5 {
        'C'
    } else {
        'D'
    };
    // A collapsed/implausible rail, impossible or extreme temperature, and a
    // CRC stream with no denominator or a double-digit error percentage are
    // catastrophic observations, not merely one item in an issue counter.
    let catastrophic = !voltage_values_plausible
        || !temperature_c.is_finite()
        || !(MIN_BOARD_TEMPERATURE_C..CRITICAL_BOARD_TEMPERATURE_C).contains(&temperature_c)
        || (crc_errors_received > 0
            && (crc_commands_sent == 0 || crc_error_rate_pct >= CRITICAL_CRC_ERROR_RATE_PCT));
    if catastrophic {
        grade = 'F';
    // An out-of-operating-range temperature, any measured CRC corruption, or
    // invalid EEPROM contents warrants at least a repair-grade D. A zero-sized
    // but otherwise clean CRC window remains C because it is missing evidence,
    // not evidence of corruption.
    } else if (!temperature_ok || !eeprom_ok || crc_errors_received > 0)
        && matches!(grade, 'A' | 'B' | 'C')
    {
        grade = 'D';
    // Other rail/CRC-window failures are not cosmetic. Only limited
    // missing-chip degradation may retain B.
    } else if (!voltage_ok || !crc_ok) && matches!(grade, 'A' | 'B') {
        grade = 'C';
    }

    BoardHealthAssessment {
        voltage_deviation_pct,
        crc_error_rate_pct,
        voltage_ok,
        crc_ok,
        temperature_ok,
        dead_chips,
        issue_count,
        grade,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_result() -> BoardHealthResult {
        BoardHealthResult {
            chain_id: 0,
            data_source: "test".into(),
            measurement_type: "dedicated_test".into(),
            status: "ok".into(),
            estimated_hashrate_ghs: 1_000.0,
            notes: Vec::new(),
            producer_context_trust: ProducerContextTrust::Unverified,
            chips_expected: 100,
            chips_responding: 100,
            dead_chip_addresses: Vec::new(),
            chip_count_evidence: DiagnosticEvidence::measured_validated(
                100,
                "bounded_asic_enumeration",
                Some(10),
            ),
            voltage_setpoint_v: 13.7,
            voltage_readback_v: 13.68,
            voltage_deviation_pct: 0.15,
            voltage_ok: true,
            voltage_evidence: DiagnosticEvidence::measured(13.68, "rail_adc", Some(10)),
            crc_commands_sent: 100,
            crc_errors_received: 0,
            crc_error_rate_pct: 0.0,
            crc_ok: true,
            crc_window_evidence: DiagnosticEvidence::measured(100, "bounded_crc_window", Some(10)),
            crc_evidence: DiagnosticEvidence::measured(0, "bounded_crc_window", Some(10)),
            temperature_c: 55.0,
            temperature_ok: true,
            temperature_evidence: DiagnosticEvidence::measured(
                55.0,
                "board_temperature_sensor",
                Some(10),
            ),
            eeprom_present: true,
            eeprom_valid: true,
            eeprom_model: Some("BHB".into()),
            eeprom_serial: Some("serial".into()),
            eeprom_presence_evidence: DiagnosticEvidence::measured_validated(
                true,
                "topology_and_eeprom_probe",
                Some(10),
            ),
            eeprom_evidence: DiagnosticEvidence::measured_validated(
                true,
                "eeprom_checksum",
                Some(10),
            ),
            required_evidence_measured: false,
            grade: 'F',
            grade_explanation: String::new(),
        }
    }

    #[test]
    fn fully_measured_healthy_board_retains_a_grade() {
        let mut result = healthy_result();
        result.calculate_grade();
        assert_eq!(result.grade, 'A');
        assert!(result.required_evidence_measured);
    }

    #[test]
    fn commanded_inferred_and_unavailable_required_evidence_cannot_pass() {
        for evidence in [
            DiagnosticEvidence::commanded(13.7, "setpoint", None),
            DiagnosticEvidence::inferred(13.7, "power_model", None),
            DiagnosticEvidence::unavailable("rail_sensor_missing"),
        ] {
            let mut result = healthy_result();
            result.voltage_evidence = evidence;
            result.calculate_grade();
            assert_eq!(result.grade, 'C');
            assert!(!result.required_evidence_measured);
            assert!(result
                .grade_explanation
                .contains("voltage evidence not measured"));
        }
    }

    #[test]
    fn inferred_eeprom_validity_cannot_produce_a_measured_pass() {
        let mut result = healthy_result();
        result.eeprom_evidence = DiagnosticEvidence::inferred(true, "model_metadata", None);
        result.calculate_grade();
        assert_eq!(result.grade, 'C');
        assert!(result
            .grade_explanation
            .contains("eeprom evidence not measured"));
    }

    #[test]
    fn unprovenanced_chip_count_or_temperature_cannot_produce_a_pass() {
        let mut missing_chip_enumeration = healthy_result();
        missing_chip_enumeration.chip_count_evidence =
            DiagnosticEvidence::inferred(100, "runtime_chain_summary", None);
        missing_chip_enumeration.calculate_grade();
        assert_eq!(missing_chip_enumeration.grade, 'C');
        assert!(missing_chip_enumeration
            .grade_explanation
            .contains("chip enumeration evidence not measured"));

        let mut missing_temperature = healthy_result();
        missing_temperature.temperature_evidence =
            DiagnosticEvidence::unavailable("temperature_source_not_recorded");
        missing_temperature.calculate_grade();
        assert_eq!(missing_temperature.grade, 'C');
        assert!(missing_temperature
            .grade_explanation
            .contains("temperature evidence not measured"));
    }

    #[test]
    fn non_finite_temperature_cannot_produce_a_pass() {
        let mut result = healthy_result();
        result.temperature_c = f32::NAN;
        result.temperature_evidence =
            DiagnosticEvidence::measured(f32::NAN, "board_temperature_sensor", Some(10));
        result.calculate_grade();
        assert_eq!(result.grade, 'F');
        assert!(!result.required_evidence_measured);
    }

    #[test]
    fn isolated_catastrophic_observations_are_not_reduced_to_issue_count() {
        let mut thermal = healthy_result();
        thermal.temperature_c = 200.0;
        thermal.temperature_evidence =
            DiagnosticEvidence::measured(200.0, "board_temperature_sensor", Some(10));
        thermal.calculate_grade();
        assert_eq!(thermal.grade, 'F');

        let mut collapsed_rail = healthy_result();
        collapsed_rail.voltage_readback_v = 0.0;
        collapsed_rail.voltage_evidence = DiagnosticEvidence::measured(0.0, "rail_adc", Some(10));
        collapsed_rail.calculate_grade();
        assert_eq!(collapsed_rail.grade, 'F');

        let mut corrupt_crc_stream = healthy_result();
        corrupt_crc_stream.crc_commands_sent = 100;
        corrupt_crc_stream.crc_errors_received = 10;
        corrupt_crc_stream.crc_evidence =
            DiagnosticEvidence::measured(10, "bounded_crc_window", Some(10));
        corrupt_crc_stream.calculate_grade();
        assert_eq!(corrupt_crc_stream.grade, 'F');
    }

    #[test]
    fn favorable_serialized_flags_cannot_override_catastrophic_observations() {
        let mut result = healthy_result();
        result.chips_expected = 0;
        result.chips_responding = 0;
        result.chip_count_evidence =
            DiagnosticEvidence::measured_validated(0, "bounded_asic_enumeration", Some(10));
        result.voltage_setpoint_v = 0.0;
        result.voltage_readback_v = 0.0;
        result.voltage_evidence = DiagnosticEvidence::measured(0.0, "rail_adc", Some(10));
        result.crc_commands_sent = 0;
        result.crc_errors_received = 999;
        result.crc_window_evidence =
            DiagnosticEvidence::measured(0, "bounded_crc_window", Some(10));
        result.crc_evidence = DiagnosticEvidence::measured(999, "bounded_crc_window", Some(10));
        result.temperature_c = 200.0;
        result.temperature_evidence =
            DiagnosticEvidence::measured(200.0, "board_temperature_sensor", Some(10));
        result.voltage_ok = true;
        result.crc_ok = true;
        result.temperature_ok = true;
        result.grade = 'A';

        result.calculate_grade();
        assert_eq!(result.grade, 'F');
        assert!(!result.voltage_ok);
        assert!(!result.crc_ok);
        assert!(!result.temperature_ok);
        assert!(!result.required_evidence_measured);
    }

    #[test]
    fn zero_crc_command_window_cannot_support_a_measured_pass() {
        let mut result = healthy_result();
        result.crc_commands_sent = 0;
        result.crc_window_evidence =
            DiagnosticEvidence::measured(0, "bounded_crc_window", Some(10));
        result.calculate_grade();
        assert_eq!(result.grade, 'C');
        assert!(!result.crc_ok);
        assert!(result
            .grade_explanation
            .contains("crc evidence not measured"));
    }

    #[test]
    fn measured_provenance_for_a_different_value_cannot_pass() {
        let mut result = healthy_result();
        result.voltage_evidence = DiagnosticEvidence::measured(13.7, "rail_adc", Some(10));
        result.calculate_grade();
        assert_eq!(result.grade, 'C');
        assert!(result
            .grade_explanation
            .contains("voltage evidence not measured"));
    }

    #[test]
    fn serialized_aggregate_evidence_claim_is_ignored_and_recomputed() {
        let mut value = serde_json::to_value(healthy_result()).unwrap();
        value["voltage_evidence"] = serde_json::json!({
            "kind": "commanded",
            "value": 13.68,
            "source": "runtime_setpoint",
            "quality": "observed"
        });
        value["required_evidence_measured"] = serde_json::json!(true);

        let mut imported: BoardHealthResult = serde_json::from_value(value).unwrap();
        assert!(!imported.required_evidence_measured);
        imported.calculate_grade();
        assert_eq!(imported.grade, 'C');
        assert!(!imported.required_evidence_measured);
    }

    #[test]
    fn legacy_payload_without_new_required_evidence_cannot_pass() {
        let mut value = serde_json::to_value(healthy_result()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("chip_count_evidence");
        object.remove("temperature_evidence");

        let mut imported: BoardHealthResult = serde_json::from_value(value).unwrap();
        imported.calculate_grade();
        assert_eq!(imported.grade, 'C');
        assert!(!imported.required_evidence_measured);
        assert!(imported
            .grade_explanation
            .contains("chip enumeration evidence not measured"));
        assert!(imported
            .grade_explanation
            .contains("temperature evidence not measured"));
    }

    #[test]
    fn producer_context_is_always_explicitly_unverified() {
        let mut legacy = serde_json::to_value(healthy_result()).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("producer_context_trust");
        let imported: BoardHealthResult = serde_json::from_value(legacy).unwrap();
        assert_eq!(
            imported.producer_context_trust,
            ProducerContextTrust::Unverified
        );

        let mut forged = serde_json::to_value(healthy_result()).unwrap();
        forged["producer_context_trust"] = serde_json::json!("verified");
        assert!(serde_json::from_value::<BoardHealthResult>(forged).is_err());
    }

    #[test]
    fn worse_health_grade_is_never_improved_by_evidence_cap() {
        let mut result = healthy_result();
        result.dead_chip_addresses = vec![1, 2, 3, 4, 5, 6];
        result.voltage_evidence = DiagnosticEvidence::commanded(13.7, "setpoint", None);
        result.calculate_grade();
        assert_eq!(result.grade, 'D');
    }
}
