//! Typed provenance for diagnostic and manufacturing evidence.
//!
//! A numeric value is not automatically a measurement. Runtime voltage
//! setpoints, zero cumulative CRC counters, model-derived EEPROM metadata and
//! absent sensor reads must remain distinguishable at every grading boundary.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Measured,
    Commanded,
    Inferred,
    Unavailable,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::Commanded => "commanded",
            Self::Inferred => "inferred",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceQuality {
    /// Direct observation with protocol/schema/checksum validation.
    Validated,
    /// Direct sensor or counter observation without stronger validation.
    Observed,
    /// Derived estimate or proxy.
    Estimated,
    /// No defensible quality statement is available.
    Unknown,
}

impl Default for EvidenceQuality {
    fn default() -> Self {
        Self::Unknown
    }
}

impl EvidenceQuality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::Observed => "observed",
            Self::Estimated => "estimated",
            Self::Unknown => "unknown",
        }
    }
}

/// One value plus the provenance needed to decide whether it can support a
/// measured diagnostic verdict. Construction helpers keep kind and quality
/// coherent; legacy deserialization defaults to explicit Unavailable evidence.
/// Direct measurements require an observation timestamp; platforms without a
/// trustworthy wall clock must use a future report-local run clock binding
/// rather than silently issuing timeless passes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticEvidence<T> {
    kind: EvidenceKind,
    value: Option<T>,
    source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observed_at_epoch_s: Option<u64>,
    quality: EvidenceQuality,
    /// Set only by test constructors that exercise the future measured-grade
    /// boundary. This deliberately does not survive serialization. Production
    /// code cannot mint it; a future v3 envelope will replace this stand-in
    /// with run/capture correlation and an explicit verification status.
    #[serde(skip)]
    live_construction_witness: bool,
}

impl<T> Default for DiagnosticEvidence<T> {
    fn default() -> Self {
        Self::unavailable("legacy_or_missing_provenance")
    }
}

impl<T> DiagnosticEvidence<T> {
    /// Test-only stand-in for the future run-bound measurement issuer.
    ///
    /// Production code deliberately has no constructor that can set the live
    /// witness. A source string and timestamp are caller assertions, not
    /// measurement authority; a production issuer must instead consume the
    /// private run/capture receipt described by the v3 evidence contract.
    #[cfg(test)]
    pub(crate) fn measured(
        value: T,
        source: impl Into<String>,
        observed_at_epoch_s: Option<u64>,
    ) -> Self {
        Self {
            kind: EvidenceKind::Measured,
            value: Some(value),
            source: source.into(),
            observed_at_epoch_s,
            quality: EvidenceQuality::Observed,
            live_construction_witness: true,
        }
    }

    /// Test-only stand-in for a parser-issued, run-bound validation receipt.
    #[cfg(test)]
    pub(crate) fn measured_validated(
        value: T,
        source: impl Into<String>,
        observed_at_epoch_s: Option<u64>,
    ) -> Self {
        Self {
            kind: EvidenceKind::Measured,
            value: Some(value),
            source: source.into(),
            observed_at_epoch_s,
            quality: EvidenceQuality::Validated,
            live_construction_witness: true,
        }
    }

    pub fn commanded(
        value: T,
        source: impl Into<String>,
        observed_at_epoch_s: Option<u64>,
    ) -> Self {
        Self {
            kind: EvidenceKind::Commanded,
            value: Some(value),
            source: source.into(),
            observed_at_epoch_s,
            quality: EvidenceQuality::Observed,
            live_construction_witness: false,
        }
    }

    pub fn inferred(value: T, source: impl Into<String>, observed_at_epoch_s: Option<u64>) -> Self {
        Self {
            kind: EvidenceKind::Inferred,
            value: Some(value),
            source: source.into(),
            observed_at_epoch_s,
            quality: EvidenceQuality::Estimated,
            live_construction_witness: false,
        }
    }

    pub fn unavailable(source: impl Into<String>) -> Self {
        Self {
            kind: EvidenceKind::Unavailable,
            value: None,
            source: source.into(),
            observed_at_epoch_s: None,
            quality: EvidenceQuality::Unknown,
            live_construction_witness: false,
        }
    }

    pub fn kind(&self) -> EvidenceKind {
        self.kind
    }

    pub fn value(&self) -> Option<&T> {
        self.value.as_ref()
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn observed_at_epoch_s(&self) -> Option<u64> {
        self.observed_at_epoch_s
    }

    pub fn quality(&self) -> EvidenceQuality {
        self.quality
    }

    /// Whether this record is coherent enough to support a measured verdict.
    ///
    /// This is deliberately stricter than checking the serialized `kind`.
    /// Imported reports are untrusted input: a measured claim without a value,
    /// a named source, or direct-observation quality fails closed.
    pub fn is_measured(&self) -> bool {
        self.kind == EvidenceKind::Measured
            && self.live_construction_witness
            && self.value.is_some()
            && !self.source.trim().is_empty()
            && self.observed_at_epoch_s.is_some()
            && matches!(
                self.quality,
                EvidenceQuality::Observed | EvidenceQuality::Validated
            )
    }
}

impl<T: PartialEq> DiagnosticEvidence<T> {
    /// Whether this evidence is measured and describes the value being graded.
    /// This prevents provenance for one observation from being attached to a
    /// different scalar field during report assembly or deserialization.
    pub fn is_measured_for(&self, value: &T) -> bool {
        self.is_measured() && self.value.as_ref() == Some(value)
    }

    /// Whether the evidence is a directly measured, independently validated
    /// observation of the exact value. Use for topology and EEPROM claims,
    /// where observing bytes/responses is insufficient without protocol or
    /// schema validation.
    pub fn is_validated_for(&self, value: &T) -> bool {
        self.is_measured_for(value) && self.quality == EvidenceQuality::Validated
    }
}

/// Shared pass-grade evidence boundary for the board observations present in
/// both BoardHealth and HashReport. Keep this list centralized so one report
/// format cannot silently accept weaker proof than the other.
// clippy::too_many_arguments: an evidence record is a flat set of independently
// captured facts; bundling them would allow a partially-populated record.
#[allow(clippy::too_many_arguments)]
pub(crate) fn required_board_evidence_gaps(
    chips_responding: u8,
    chip_count_evidence: &DiagnosticEvidence<u8>,
    temperature_c: f32,
    temperature_evidence: &DiagnosticEvidence<f32>,
    voltage_v: f32,
    voltage_evidence: &DiagnosticEvidence<f32>,
    crc_commands_sent: u32,
    crc_window_evidence: &DiagnosticEvidence<u32>,
    crc_errors: u32,
    crc_evidence: &DiagnosticEvidence<u32>,
    eeprom_present: bool,
    eeprom_presence_evidence: &DiagnosticEvidence<bool>,
    eeprom_valid: bool,
    eeprom_validity_evidence: &DiagnosticEvidence<bool>,
) -> Vec<&'static str> {
    let mut gaps = Vec::new();
    if !chip_count_evidence.is_validated_for(&chips_responding) {
        gaps.push("chip enumeration");
    }
    if !temperature_c.is_finite() || !temperature_evidence.is_measured_for(&temperature_c) {
        gaps.push("temperature");
    }
    if !voltage_v.is_finite() || !voltage_evidence.is_measured_for(&voltage_v) {
        gaps.push("voltage");
    }
    if crc_commands_sent == 0
        || !crc_window_evidence.is_measured_for(&crc_commands_sent)
        || !crc_evidence.is_measured_for(&crc_errors)
    {
        gaps.push("crc");
    }
    if !eeprom_presence_evidence.is_validated_for(&eeprom_present)
        || (eeprom_present && !eeprom_validity_evidence.is_validated_for(&eeprom_valid))
    {
        gaps.push("eeprom");
    }
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_measurement_issuers_remain_absent_until_v3_receipts_exist() {
        let source = include_str!("evidence.rs").replace("\r\n", "\n");
        assert!(source.contains("#[cfg(test)]\n    pub(crate) fn measured("));
        assert!(source.contains("#[cfg(test)]\n    pub(crate) fn measured_validated("));
        assert!(!source.contains("\n    pub fn measured("));
        assert!(!source.contains("\n    pub fn measured_validated("));
    }

    #[test]
    fn missing_legacy_evidence_is_explicitly_unavailable() {
        let evidence = DiagnosticEvidence::<u16>::default();
        assert_eq!(evidence.kind(), EvidenceKind::Unavailable);
        assert_eq!(evidence.value(), None);
        assert!(!evidence.is_measured());
        assert_eq!(evidence.quality(), EvidenceQuality::Unknown);
    }

    #[test]
    fn only_measured_constructors_satisfy_measured_requirement() {
        let cases = [
            DiagnosticEvidence::commanded(13_700u16, "setpoint", None),
            DiagnosticEvidence::inferred(13_700u16, "model", None),
            DiagnosticEvidence::unavailable("sensor_missing"),
        ];
        for evidence in cases {
            assert!(!evidence.is_measured());
        }
        assert!(DiagnosticEvidence::measured(13_690u16, "rail_adc", Some(1)).is_measured());
    }

    #[test]
    fn incoherent_serialized_measured_claims_fail_closed() {
        for json in [
            r#"{"kind":"measured","value":13690,"source":"","quality":"observed"}"#,
            r#"{"kind":"measured","value":13690,"source":"   ","quality":"validated"}"#,
            r#"{"kind":"measured","value":null,"source":"rail_adc","quality":"observed"}"#,
            r#"{"kind":"measured","value":13690,"source":"rail_adc","quality":"estimated"}"#,
            r#"{"kind":"measured","value":13690,"source":"rail_adc","quality":"unknown"}"#,
            r#"{"kind":"measured","value":13690,"source":"rail_adc","quality":"observed"}"#,
        ] {
            let evidence: DiagnosticEvidence<u16> = serde_json::from_str(json).unwrap();
            assert!(!evidence.is_measured(), "accepted incoherent claim: {json}");
        }
    }

    #[test]
    fn measured_evidence_must_match_the_value_being_graded() {
        let evidence = DiagnosticEvidence::measured(13_690u16, "rail_adc", Some(1));
        assert!(evidence.is_measured_for(&13_690));
        assert!(!evidence.is_measured_for(&13_700));
    }

    #[test]
    fn serialized_measured_claim_cannot_recreate_live_authority() {
        let live =
            DiagnosticEvidence::measured_validated(108u8, "bounded_asic_enumeration", Some(1));
        assert!(live.is_validated_for(&108));

        let wire = serde_json::to_value(&live).unwrap();
        let imported: DiagnosticEvidence<u8> = serde_json::from_value(wire).unwrap();
        assert_eq!(imported.kind(), EvidenceKind::Measured);
        assert_eq!(imported.value(), Some(&108));
        assert!(!imported.is_measured());
        assert!(!imported.is_validated_for(&108));
    }

    #[test]
    fn shared_board_boundary_requires_every_graded_observation() {
        let chips = DiagnosticEvidence::measured_validated(100u8, "asic_enumeration", Some(1));
        let temp = DiagnosticEvidence::measured(55.0f32, "temp_sensor", Some(1));
        let voltage = DiagnosticEvidence::measured(13.7f32, "rail_adc", Some(1));
        let crc = DiagnosticEvidence::measured(0u32, "crc_window", Some(1));
        let crc_window = DiagnosticEvidence::measured(100u32, "crc_window", Some(1));
        let eeprom_presence = DiagnosticEvidence::measured_validated(false, "topology", Some(1));
        assert!(required_board_evidence_gaps(
            100,
            &chips,
            55.0,
            &temp,
            13.7,
            &voltage,
            100,
            &crc_window,
            0,
            &crc,
            false,
            &eeprom_presence,
            false,
            &DiagnosticEvidence::unavailable("not_applicable"),
        )
        .is_empty());

        let gaps = required_board_evidence_gaps(
            100,
            &DiagnosticEvidence::inferred(100, "runtime", None),
            f32::NAN,
            &temp,
            13.7,
            &voltage,
            0,
            &DiagnosticEvidence::unavailable("no_window"),
            0,
            &DiagnosticEvidence::inferred(0, "cumulative", None),
            false,
            &DiagnosticEvidence::unavailable("not_observed"),
            false,
            &DiagnosticEvidence::unavailable("not_observed"),
        );
        assert_eq!(
            gaps,
            vec!["chip enumeration", "temperature", "crc", "eeprom"]
        );
    }
}
