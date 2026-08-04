//! Honest diagnostic run-mode labels (decade backlog P2-5).
//!
//! # Why
//!
//! HashReport and board-health producers historically used free-form
//! `report_kind` / `measurement_type` strings. A snapshot of passive runtime
//! state must never be marketed as an active stimulation / timed stress pass
//! that can support measured manufacturing grades. This module is the pure
//! vocabulary for that honesty boundary — HAL-free so host tests and the
//! diagnostics crate share one refuse language.
//!
//! # Status
//!
//! **Production pure labels.** Snapshot builders already emit `report_kind =
//! "snapshot"` and `measurement_type = "live_snapshot"`; call
//! [`admit_report_kind`] before publishing any new report so a refactor cannot
//! re-label a snapshot as active stim. Active-stim engine wiring remains a
//! strangler residual until the dedicated timed diagnostic path is complete.

/// How the diagnostic data was collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiagnosticRunMode {
    /// Passive read of current runtime state — no dedicated stress / stim.
    Snapshot,
    /// Timed / active stimulation diagnostic engine ran against hardware.
    ActiveStim,
}

impl DiagnosticRunMode {
    /// Canonical `report_kind` wire value.
    pub const fn as_report_kind(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::ActiveStim => "active_stim",
        }
    }

    /// Canonical `measurement_type` wire value used by board-health cells.
    pub const fn as_measurement_type(self) -> &'static str {
        match self {
            Self::Snapshot => "live_snapshot",
            Self::ActiveStim => "active_stim",
        }
    }

    /// Snapshot mode alone cannot support a measured manufacturing pass.
    ///
    /// Even ActiveStim still requires typed measured evidence (v3 contract);
    /// this only answers "did a stim engine even run?"
    pub const fn can_claim_measured_pass_authority(self) -> bool {
        matches!(self, Self::ActiveStim)
    }
}

/// Why a report_kind / mode pair was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticModeError {
    /// Free-form label is not a known honest mode.
    UnknownReportKind { report_kind: String },
    /// Producer mode and claimed label disagree (e.g. snapshot claiming stim).
    ModeMismatch {
        mode: DiagnosticRunMode,
        report_kind: String,
    },
}

impl std::fmt::Display for DiagnosticModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownReportKind { report_kind } => {
                write!(f, "unknown diagnostic report_kind: {report_kind}")
            }
            Self::ModeMismatch { mode, report_kind } => write!(
                f,
                "diagnostic mode {mode:?} cannot claim report_kind={report_kind}"
            ),
        }
    }
}

impl std::error::Error for DiagnosticModeError {}

/// Parse a wire `report_kind` into a mode (accepts legacy timed aliases).
pub fn parse_report_kind(report_kind: &str) -> Option<DiagnosticRunMode> {
    match report_kind {
        "snapshot" => Some(DiagnosticRunMode::Snapshot),
        "active_stim" | "timed" | "timed_active" | "timed-v1" | "timed-v2" => {
            Some(DiagnosticRunMode::ActiveStim)
        }
        _ => None,
    }
}

/// Fail closed when a producer mode and a claimed report_kind disagree.
pub fn admit_report_kind(
    mode: DiagnosticRunMode,
    report_kind: &str,
) -> Result<(), DiagnosticModeError> {
    let parsed =
        parse_report_kind(report_kind).ok_or_else(|| DiagnosticModeError::UnknownReportKind {
            report_kind: report_kind.to_string(),
        })?;
    if parsed != mode {
        return Err(DiagnosticModeError::ModeMismatch {
            mode,
            report_kind: report_kind.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_wire_labels_are_stable() {
        assert_eq!(DiagnosticRunMode::Snapshot.as_report_kind(), "snapshot");
        assert_eq!(
            DiagnosticRunMode::Snapshot.as_measurement_type(),
            "live_snapshot"
        );
        assert!(!DiagnosticRunMode::Snapshot.can_claim_measured_pass_authority());
    }

    #[test]
    fn active_stim_is_the_only_measured_pass_authority_mode() {
        assert!(DiagnosticRunMode::ActiveStim.can_claim_measured_pass_authority());
        assert_eq!(
            DiagnosticRunMode::ActiveStim.as_report_kind(),
            "active_stim"
        );
    }

    #[test]
    fn admit_refuses_snapshot_claiming_active_stim() {
        let err = admit_report_kind(DiagnosticRunMode::Snapshot, "active_stim").unwrap_err();
        assert!(matches!(err, DiagnosticModeError::ModeMismatch { .. }));
    }

    #[test]
    fn admit_accepts_honest_snapshot() {
        assert!(admit_report_kind(DiagnosticRunMode::Snapshot, "snapshot").is_ok());
    }

    #[test]
    fn admit_accepts_legacy_timed_aliases_as_active_stim() {
        for kind in ["active_stim", "timed", "timed_active", "timed-v2"] {
            assert!(
                admit_report_kind(DiagnosticRunMode::ActiveStim, kind).is_ok(),
                "expected ok for {kind}"
            );
        }
    }

    #[test]
    fn admit_refuses_unknown_kind() {
        assert!(matches!(
            admit_report_kind(DiagnosticRunMode::Snapshot, "magic"),
            Err(DiagnosticModeError::UnknownReportKind { .. })
        ));
    }
}
