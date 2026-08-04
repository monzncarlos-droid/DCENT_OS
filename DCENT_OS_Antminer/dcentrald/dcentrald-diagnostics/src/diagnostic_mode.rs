//! Diagnostics façade for honest run-mode labels (P2-5).
//!
//! Policy lives in [`dcentrald_common::diagnostic_mode`] so host tests do not
//! need HAL. This module re-exports the common vocabulary and adds the
//! Measurement → EvidenceKind bridge used by graded report producers.

pub use dcentrald_common::{
    admit_report_kind, parse_report_kind, DiagnosticModeError, DiagnosticRunMode,
};

/// Map universal [`dcentrald_common::MeasurementProvenance`] into diagnostic
/// [`crate::evidence::EvidenceKind`] without inventing a parallel vocabulary.
pub fn evidence_kind_from_measurement_provenance(
    p: dcentrald_common::MeasurementProvenance,
) -> crate::evidence::EvidenceKind {
    use crate::evidence::EvidenceKind;
    use dcentrald_common::MeasurementProvenance;
    match p {
        MeasurementProvenance::Measured => EvidenceKind::Measured,
        MeasurementProvenance::CommandedNotMeasured | MeasurementProvenance::CommandedDefault => {
            EvidenceKind::Commanded
        }
        MeasurementProvenance::Modeled => EvidenceKind::Inferred,
        MeasurementProvenance::Unknown => EvidenceKind::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::EvidenceKind;
    use dcentrald_common::MeasurementProvenance;

    #[test]
    fn measurement_provenance_maps_to_evidence_kind() {
        assert_eq!(
            evidence_kind_from_measurement_provenance(MeasurementProvenance::Measured),
            EvidenceKind::Measured
        );
        assert_eq!(
            evidence_kind_from_measurement_provenance(MeasurementProvenance::CommandedNotMeasured),
            EvidenceKind::Commanded
        );
        assert_eq!(
            evidence_kind_from_measurement_provenance(MeasurementProvenance::Modeled),
            EvidenceKind::Inferred
        );
        assert_eq!(
            evidence_kind_from_measurement_provenance(MeasurementProvenance::Unknown),
            EvidenceKind::Unavailable
        );
    }

    #[test]
    fn common_snapshot_honesty_is_reexported() {
        assert!(admit_report_kind(DiagnosticRunMode::Snapshot, "snapshot").is_ok());
        assert!(admit_report_kind(DiagnosticRunMode::Snapshot, "active_stim").is_err());
    }
}
