//! HashReport result model and completion-snapshot engine.
//!
//! The current background job waits for the requested interval, then builds a
//! report from completion-time runtime state and retained global history. It
//! does not yet own an internal pool or capture report-bound per-window nonce,
//! CRC, and sensor evidence. The five phases below describe the target active
//! diagnostic; snapshot reports remain evidence-capped until those producers
//! are wired.
//!
//! Phases:
//!   1. System Identification (10 seconds)
//!   2. Baseline Capture (30 seconds)
//!   3. Mining Performance (12 minutes, 12 x 60s windows)
//!   4. Per-Chip Health Scoring (2 minutes)
//!   5. Report Generation (20 seconds)

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::board_health::assess_board_health;
use crate::evidence::{required_board_evidence_gaps, DiagnosticEvidence};

/// HashReport test phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashReportPhase {
    /// Phase 1: Read serial, MAC, chip type, FPGA version, board count.
    SystemIdentification,
    /// Phase 2: Read temperatures, fan speed, PSU, voltage, CRC baseline.
    BaselineCapture,
    /// Phase 3: 12 x 60s mining windows, count nonces per chip.
    MiningPerformance,
    /// Phase 4: Calculate per-chip health scores and grades.
    ChipHealthScoring,
    /// Phase 5: Aggregate results, generate HTML report.
    ReportGeneration,
}

/// System identification data (Phase 1 output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Miner serial number (from EEPROM or MAC-derived).
    pub serial: String,
    /// MAC address.
    pub mac: String,
    /// Miner model (e.g., "Antminer S9").
    pub model: String,
    /// ASIC chip type (e.g., "BM1387").
    pub chip_type: String,
    /// Chip ID hex (e.g., "0x1387").
    pub chip_id: String,
    /// FPGA version (e.g., "0x00901002").
    pub fpga_version: String,
    /// Number of hash boards detected.
    pub board_count: u8,
    /// Total chips across all boards.
    pub total_chips: u16,
    /// Control board type (e.g., "Zynq C55").
    pub control_board: String,
}

/// Baseline snapshot (Phase 2 output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    /// Per-chain temperatures in celsius.
    pub temperatures_c: Vec<f32>,
    /// Fan RPM at baseline.
    pub fan_rpm: u32,
    /// Fan PWM at baseline.
    pub fan_pwm: u8,
    /// Per-chain voltages in volts.
    pub voltages_v: Vec<f32>,
    /// Per-chain CRC error baseline counts.
    pub crc_baseline: Vec<u32>,
}

/// One 60-second performance measurement window (Phase 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowData {
    /// Window index (0-11).
    pub window_index: u8,
    /// Per-chip nonce counts for this window.
    pub chip_nonces: Vec<u32>,
    /// Per-chain CRC errors during this window.
    pub chain_crc_errors: Vec<u32>,
    /// Per-chain temperature at end of window.
    pub chain_temps_c: Vec<f32>,
    /// Total valid nonces in this window.
    pub total_nonces: u64,
}

/// Per-chip health score (Phase 4 output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChipHealthScore {
    /// Chip index within the chain.
    pub index: u16,
    /// Chip address.
    pub address: u8,
    /// Health grade: A, B, C, D, or F.
    pub grade: char,
    /// Health score (0.0 to 1.0+).
    pub health_score: f32,
    /// Total nonces found across all windows.
    pub nonce_count: u64,
    /// Expected nonces based on frequency and difficulty.
    pub expected_nonces: u64,
    /// CRC errors attributed to this chip.
    pub crc_errors: u32,
    /// Current frequency in MHz.
    pub frequency_mhz: u16,
    /// Estimated hashrate in GH/s.
    pub hashrate_ghs: f32,
}

/// Complete HashReport result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashReport {
    /// Unique report identifier.
    pub report_id: Uuid,
    /// Report format version.
    pub report_version: String,
    /// ISO 8601 timestamp of report generation.
    pub generated_at: String,
    /// Total test duration in seconds.
    pub duration_seconds: u32,
    /// Honest labeling for timed drive vs snapshot report.
    pub report_kind: String,
    /// High-level data source used to build the report.
    pub source: String,
    /// Firmware version.
    pub firmware_version: String,
    /// System identification.
    pub system: SystemInfo,
    /// Baseline measurements.
    pub baseline: BaselineSnapshot,
    /// Performance windows data.
    pub windows: Vec<WindowData>,
    /// Per-board results with chip health.
    pub boards: Vec<BoardResult>,
    /// Overall unit grade: A, B, C, D, or F.
    pub unit_grade: char,
    /// Explanation of the grade.
    pub unit_grade_explanation: String,
    /// Generated warnings.
    pub warnings: Vec<String>,
    /// Recommendations for the user.
    pub recommendations: Vec<String>,
}

/// Per-board result within a HashReport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardResult {
    /// Chain ID (6, 7, or 8).
    pub chain_id: u8,
    /// Expected chip count.
    pub chips_expected: u8,
    /// Responding chip count.
    pub chips_responding: u8,
    /// Provenance for the responding-chip enumeration.
    #[serde(default)]
    pub chip_count_evidence: DiagnosticEvidence<u8>,
    /// Dead chip count (0 nonces across all windows).
    pub chips_dead: u8,
    /// Board hashrate in GH/s.
    pub hashrate_ghs: f32,
    /// Board voltage in volts.
    pub voltage_v: f32,
    /// Provenance for `voltage_v`.
    #[serde(default)]
    pub voltage_evidence: DiagnosticEvidence<f32>,
    /// Board temperature in celsius.
    pub temp_c: f32,
    /// Provenance for the board-temperature observation.
    #[serde(default)]
    pub temperature_evidence: DiagnosticEvidence<f32>,
    /// Total CRC errors.
    pub crc_errors: u32,
    /// Number of commands in the bounded CRC observation window.
    #[serde(default)]
    pub crc_commands_sent: u32,
    /// Provenance for the bounded command count.
    #[serde(default)]
    pub crc_window_evidence: DiagnosticEvidence<u32>,
    /// Provenance for the CRC observation/window.
    #[serde(default)]
    pub crc_evidence: DiagnosticEvidence<u32>,
    /// Whether an EEPROM was observed on this board.
    #[serde(default)]
    pub eeprom_present: bool,
    /// Validated EEPROM presence/absence observation.
    #[serde(default)]
    pub eeprom_presence_evidence: DiagnosticEvidence<bool>,
    /// EEPROM checksum/schema validity when present.
    #[serde(default)]
    pub eeprom_valid: bool,
    /// Validated EEPROM contents observation when present.
    #[serde(default)]
    pub eeprom_evidence: DiagnosticEvidence<bool>,
    /// Board grade: A, B, C, D, or F.
    pub grade: char,
    /// Per-chip health scores.
    pub chips: Vec<ChipHealthScore>,
}

#[cfg(test)]
mod unit_grade_tests {
    use super::*;

    fn board(chips_dead: u8, grade: char) -> BoardResult {
        BoardResult {
            chain_id: 0,
            chips_expected: 108,
            chips_responding: 108u8.saturating_sub(chips_dead),
            chip_count_evidence: DiagnosticEvidence::measured_validated(
                108u8.saturating_sub(chips_dead),
                "bounded_asic_enumeration",
                Some(1),
            ),
            chips_dead,
            hashrate_ghs: 0.0,
            voltage_v: 13.7,
            voltage_evidence: DiagnosticEvidence::measured(13.7, "rail_adc", Some(1)),
            temp_c: 60.0,
            temperature_evidence: DiagnosticEvidence::measured(
                60.0,
                "board_temperature_sensor",
                Some(1),
            ),
            crc_errors: 0,
            crc_commands_sent: 100,
            crc_window_evidence: DiagnosticEvidence::measured(100, "crc_window", Some(1)),
            crc_evidence: DiagnosticEvidence::measured(0, "crc_window", Some(1)),
            eeprom_present: false,
            eeprom_presence_evidence: DiagnosticEvidence::measured_validated(
                false,
                "board_topology",
                Some(1),
            ),
            eeprom_valid: false,
            eeprom_evidence: DiagnosticEvidence::unavailable("not_applicable"),
            grade,
            chips: Vec::new(),
        }
    }

    #[test]
    fn calculate_unit_grade_does_not_overflow_to_false_pass() {
        // 86+85+85 = 256 dead chips → wraps to 0 in a u8 accumulator. The OLD
        // code graded this all-'A'-labeled set 'A' (FALSE PASS on a dead unit);
        // the u32 accumulator grades it 'F' (256 > 3*6). (gap-swarm HAL-safety #7)
        let boards = vec![board(86, 'A'), board(85, 'A'), board(85, 'A')];
        assert_eq!(calculate_unit_grade(&boards), 'F');
    }

    #[test]
    fn calculate_unit_grade_is_monotonic_and_never_wraps_to_a_false_pass() {
        // Property (strengthens the single 256-case pin above): across dead-chip
        // counts sweeping PAST the u8 wrap points (256, 512), the unit grade must be
        // MONOTONICALLY non-improving — more dead chips can NEVER yield a better
        // grade. A regression of total_dead to a narrower type would wrap (256->0,
        // 324->68) and make a MORE-dead unit grade BETTER, which this monotonicity
        // check catches anywhere in the range (not just at 256). Three A-graded
        // boards, so the grade is driven purely by the dead count.
        let rank = |g: char| match g {
            'A' => 4,
            'B' => 3,
            'C' => 2,
            'D' => 1,
            _ => 0,
        };
        let mut prev = 5; // better than any real grade
        for dead in [0u8, 1, 2, 3, 50, 85, 86, 100, 170, 200, 255] {
            let boards = vec![board(dead, 'A'), board(dead, 'A'), board(dead, 'A')];
            let r = rank(calculate_unit_grade(&boards));
            assert!(
                r <= prev,
                "grade IMPROVED (rank {prev} -> {r}) as dead chips rose to {dead}/board — u8-wrap false-pass regression"
            );
            prev = r;
        }
        // 255*3 = 765 dead is unambiguously a dead unit -> worst grade.
        assert_eq!(
            calculate_unit_grade(&[board(255, 'A'), board(255, 'A'), board(255, 'A')]),
            'F'
        );
    }

    #[test]
    fn calculate_unit_grade_in_range_unchanged() {
        assert_eq!(calculate_unit_grade(&[]), 'F');
        assert_eq!(calculate_unit_grade(&[board(0, 'A')]), 'A');
        assert_eq!(calculate_unit_grade(&[board(1, 'A')]), 'B'); // 1 dead > 0 → B
    }
    #[test]
    fn commanded_or_inferred_board_evidence_cannot_produce_unit_pass() {
        let mut commanded = board(0, 'A');
        commanded.voltage_evidence = DiagnosticEvidence::commanded(13.7, "runtime_setpoint", None);
        assert_eq!(calculate_unit_grade(&[commanded]), 'C');

        let mut inferred = board(0, 'A');
        inferred.crc_evidence = DiagnosticEvidence::inferred(0, "cumulative_counter", None);
        assert_eq!(calculate_unit_grade(&[inferred]), 'C');

        let mut inferred_chips = board(0, 'A');
        inferred_chips.chip_count_evidence =
            DiagnosticEvidence::inferred(108, "runtime_chain_summary", None);
        assert_eq!(calculate_unit_grade(&[inferred_chips]), 'C');

        let mut unprovenanced_temperature = board(0, 'A');
        unprovenanced_temperature.temperature_evidence =
            DiagnosticEvidence::unavailable("temperature_source_not_recorded");
        assert_eq!(calculate_unit_grade(&[unprovenanced_temperature]), 'C');
    }

    #[test]
    fn unavailable_legacy_evidence_is_not_silently_accepted() {
        let mut legacy = board(0, 'A');
        legacy.voltage_evidence = DiagnosticEvidence::default();
        legacy.crc_evidence = DiagnosticEvidence::default();
        assert_eq!(calculate_unit_grade(&[legacy]), 'C');
    }

    #[test]
    fn legacy_board_payload_without_new_required_evidence_cannot_pass() {
        let mut value = serde_json::to_value(board(0, 'A')).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("chip_count_evidence");
        object.remove("temperature_evidence");

        let imported: BoardResult = serde_json::from_value(value).unwrap();
        assert_eq!(calculate_unit_grade(&[imported]), 'C');
    }

    #[test]
    fn serialized_grade_and_flags_cannot_override_raw_board_health() {
        let mut catastrophic = board(0, 'A');
        catastrophic.chips_expected = 0;
        catastrophic.chips_responding = 0;
        catastrophic.chip_count_evidence =
            DiagnosticEvidence::measured_validated(0, "bounded_asic_enumeration", Some(1));
        catastrophic.temp_c = 200.0;
        catastrophic.temperature_evidence =
            DiagnosticEvidence::measured(200.0, "temp_sensor", Some(1));
        catastrophic.voltage_v = 0.0;
        catastrophic.voltage_evidence = DiagnosticEvidence::measured(0.0, "rail_adc", Some(1));
        catastrophic.crc_commands_sent = 0;
        catastrophic.crc_errors = 999;
        catastrophic.crc_window_evidence = DiagnosticEvidence::measured(0, "crc_window", Some(1));
        catastrophic.crc_evidence = DiagnosticEvidence::measured(999, "crc_window", Some(1));
        catastrophic.grade = 'A';
        catastrophic.chips_dead = 0;
        assert_eq!(calculate_unit_grade(&[catastrophic]), 'F');

        let mut invalid_grade = board(0, 'Z');
        invalid_grade.grade = 'Z';
        assert_eq!(calculate_unit_grade(&[invalid_grade]), 'A');
    }

    #[test]
    fn board_grade_applies_the_same_evidence_cap_as_unit_grade() {
        let mut unprovenanced = board(0, 'A');
        unprovenanced.voltage_evidence =
            DiagnosticEvidence::commanded(13.7, "runtime_setpoint", None);
        assert_eq!(calculate_board_grade(&unprovenanced), 'C');
        assert_eq!(calculate_unit_grade(&[unprovenanced]), 'C');
    }

    #[test]
    fn degraded_per_chip_data_cannot_be_hidden_by_favorable_aggregates() {
        let mut degraded = board(0, 'A');
        degraded.chips.push(ChipHealthScore {
            index: 0,
            address: 0,
            grade: 'A',
            health_score: 0.30,
            nonce_count: 10,
            expected_nonces: 10,
            crc_errors: 0,
            frequency_mhz: 500,
            hashrate_ghs: 100.0,
        });
        assert_eq!(calculate_chip_grade(&degraded.chips[0]), 'D');
        assert_eq!(calculate_board_grade(&degraded), 'D');
        assert_eq!(calculate_unit_grade(&[degraded]), 'D');
    }

    #[test]
    fn canonicalization_replaces_stale_verdict_narratives() {
        let mut unprovenanced = board(0, 'A');
        unprovenanced.voltage_evidence =
            DiagnosticEvidence::commanded(13.7, "runtime_setpoint", None);
        let mut report = HashReport {
            report_id: Uuid::nil(),
            report_version: "snapshot-v2".into(),
            generated_at: "test".into(),
            duration_seconds: 0,
            report_kind: "snapshot".into(),
            source: "test".into(),
            firmware_version: "test".into(),
            system: SystemInfo {
                serial: "test".into(),
                mac: "test".into(),
                model: "test".into(),
                chip_type: "test".into(),
                chip_id: "test".into(),
                fpga_version: "test".into(),
                board_count: 1,
                total_chips: 108,
                control_board: "test".into(),
            },
            baseline: BaselineSnapshot {
                temperatures_c: Vec::new(),
                fan_rpm: 0,
                fan_pwm: 0,
                voltages_v: Vec::new(),
                crc_baseline: Vec::new(),
            },
            windows: Vec::new(),
            boards: vec![unprovenanced],
            unit_grade: 'A',
            unit_grade_explanation: "trusted serialized pass".into(),
            warnings: vec!["everything passed".into()],
            recommendations: vec!["ship immediately".into()],
        };

        canonicalize_hashreport(&mut report);
        assert_eq!(report.unit_grade, 'C');
        assert_eq!(report.boards[0].grade, 'C');
        assert!(report.unit_grade_explanation.contains("Canonical grade C"));
        assert!(!report.unit_grade_explanation.contains("trusted"));
        assert!(!report
            .warnings
            .iter()
            .any(|warning| warning.contains("everything")));
        assert!(!report
            .recommendations
            .iter()
            .any(|recommendation| recommendation.contains("ship")));
    }
}

/// Assign a health grade based on score.
pub fn score_to_grade(score: f32) -> char {
    if score >= 0.90 {
        'A'
    } else if score >= 0.75 {
        'B'
    } else if score >= 0.50 {
        'C'
    } else if score >= 0.25 {
        'D'
    } else {
        'F'
    }
}

/// Calculate overall unit grade from board grades.
pub fn calculate_unit_grade(boards: &[BoardResult]) -> char {
    if boards.is_empty() {
        return 'F';
    }

    // u32 accumulator: per-board chips_dead is u8 but a multi-board unit can have
    // far more than 255 dead chips total (3 boards × up to ~108-894 each). A u8
    // sum would overflow → panic in debug, or SILENTLY WRAP in release (256→0,
    // 324→68), yielding a BETTER grade than reality (false-pass on a dead unit) —
    // exactly the worst case this verdict exists to catch. (gap-swarm HAL-safety #7)
    let assessments = boards
        .iter()
        .map(calculate_board_assessment)
        .collect::<Vec<_>>();
    let total_dead: u32 = assessments
        .iter()
        .map(|assessment| assessment.dead_chips as u32)
        .sum();
    let worst_grade = assessments
        .iter()
        .map(|assessment| assessment.grade)
        .max()
        .unwrap_or('F');

    let health_grade = if worst_grade == 'F' || total_dead > boards.len() as u32 * 6 {
        'F'
    } else if worst_grade == 'D' || total_dead > 5 {
        'D'
    } else if worst_grade == 'C' || total_dead > 2 {
        'C'
    } else if worst_grade == 'B' || total_dead > 0 {
        'B'
    } else {
        'A'
    };

    let required_evidence_measured = boards
        .iter()
        .all(|board| board_evidence_gaps(board).is_empty());
    if !required_evidence_measured && matches!(health_grade, 'A' | 'B') {
        'C'
    } else {
        health_grade
    }
}

fn calculate_board_assessment(board: &BoardResult) -> crate::board_health::BoardHealthAssessment {
    let per_chip_dead = board
        .chips
        .iter()
        .filter(|chip| {
            chip.health_score <= 0.01 || (chip.expected_nonces > 0 && chip.nonce_count == 0)
        })
        .count();
    let mut assessment = assess_board_health(
        board.chips_expected,
        board.chips_responding,
        usize::from(board.chips_dead).max(per_chip_dead),
        board.voltage_v,
        board.voltage_v,
        board.crc_commands_sent,
        board.crc_errors,
        board.temp_c,
        board.eeprom_present,
        board.eeprom_valid,
    );
    if let Some(worst_chip_grade) = board.chips.iter().map(calculate_chip_grade).max() {
        assessment.grade = assessment.grade.max(worst_chip_grade);
    }
    assessment
}

fn board_evidence_gaps(board: &BoardResult) -> Vec<&'static str> {
    required_board_evidence_gaps(
        board.chips_responding,
        &board.chip_count_evidence,
        board.temp_c,
        &board.temperature_evidence,
        board.voltage_v,
        &board.voltage_evidence,
        board.crc_commands_sent,
        &board.crc_window_evidence,
        board.crc_errors,
        &board.crc_evidence,
        board.eeprom_present,
        &board.eeprom_presence_evidence,
        board.eeprom_valid,
        &board.eeprom_evidence,
    )
}

/// Canonical per-chip grade derived from raw score/counters. Serialized
/// `ChipHealthScore::grade` is only a display cache.
pub(crate) fn calculate_chip_grade(chip: &ChipHealthScore) -> char {
    if !chip.health_score.is_finite()
        || chip.health_score < 0.0
        || !chip.hashrate_ghs.is_finite()
        || chip.hashrate_ghs < 0.0
        || (chip.expected_nonces > 0 && chip.nonce_count == 0)
    {
        return 'F';
    }
    let grade = score_to_grade(chip.health_score);
    if chip.crc_errors > 0 && matches!(grade, 'A' | 'B') {
        'C'
    } else {
        grade
    }
}

/// Canonical health-and-evidence-derived board grade. Serialized `grade` is a
/// display cache and never grading authority. Board and unit passing verdicts
/// deliberately share the same evidence boundary.
pub fn calculate_board_grade(board: &BoardResult) -> char {
    let health_grade = calculate_board_assessment(board).grade;
    if !board_evidence_gaps(board).is_empty() && matches!(health_grade, 'A' | 'B') {
        'C'
    } else {
        health_grade
    }
}

/// Recompute every verdict and narrative cache that can influence a persisted
/// or rendered HashReport. Producer-supplied prose is intentionally replaced:
/// it cannot remain authoritative after a report is regraded.
pub(crate) fn canonicalize_hashreport(report: &mut HashReport) {
    for board in &mut report.boards {
        for chip in &mut board.chips {
            chip.grade = calculate_chip_grade(chip);
        }
        board.grade = calculate_board_grade(board);
    }
    report.unit_grade = calculate_unit_grade(&report.boards);

    let boards_with_gaps = report
        .boards
        .iter()
        .filter(|board| !board_evidence_gaps(board).is_empty())
        .count();
    report.unit_grade_explanation = format!(
        "Canonical grade {} from {} board(s), recomputed from raw topology, voltage, CRC, temperature, EEPROM, per-chip data, and typed evidence. {} board(s) lack complete evidence required for an A/B verdict.",
        report.unit_grade,
        report.boards.len(),
        boards_with_gaps,
    );

    report.warnings = report
        .boards
        .iter()
        .filter_map(|board| {
            let gaps = board_evidence_gaps(board);
            (!gaps.is_empty()).then(|| {
                format!(
                    "Chain {} lacks passing-grade evidence: {}.",
                    board.chain_id,
                    gaps.join(", ")
                )
            })
        })
        .collect();
    for board in &report.boards {
        if matches!(board.grade, 'D' | 'F') {
            report.warnings.push(format!(
                "Chain {} has canonical board grade {} and requires investigation.",
                board.chain_id, board.grade
            ));
        }
    }
    report.warnings.sort();
    report.warnings.dedup();

    report.recommendations = if matches!(report.unit_grade, 'A' | 'B') {
        vec!["Continue scheduled monitoring; this verdict applies only to the recorded evidence window."
            .to_string()]
    } else {
        vec![
            "Run a bounded active diagnostic with validated chip enumeration, rail and temperature observations, CRC window correlation, and EEPROM validation before manufacturing or repair sign-off."
                .to_string(),
        ]
    };
}
