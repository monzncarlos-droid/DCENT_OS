//! Cooling custody policy — C52 fail-closed for home AM2 profiles (P1-7).
//!
//! # Why
//!
//! On XIL S19j Pro class hardware (`a lab unit`), the control board can boot in C49
//! 1-PWM mode. Only two fans then follow `fan-control` PWM, and tach channels
//! 2/3 stay zero — a home unit can look "quiet" while half the airflow is
//! uncontrolled. Live-proven fix: board-control `+0x04` low byte → C52
//! (`0x34`) before mining energize.
//!
//! Soft-fail ("warn and mine") is a **lab risk** on industrial benches; on a
//! residential/home profile it is a safety defect. This module is the pure
//! policy chokepoint: home + AM2-S19-family ⇒ C52 receipt required, else refuse
//! energize. HAL adapters apply the write; they must not invent a different
//! home rule.
//!
//! # Status
//!
//! **Production policy types** (host-testable). Live write remains in
//! `dcentrald-hal::board_control` / `FanController`; exact S19 routes already
//! use `ZynqPlatform::open_am2_s19_fan_controller_checked`. New home/AM2
//! admission must consult [`admit_c52_custody`] before rail enable.

/// Live-proven C52 mode low byte on `board-control +0x04`.
pub const C52_MODE_LOW_BYTE: u8 = 0x34;

/// C49 1-PWM mode low byte (the quiet-fan defect mode).
pub const C49_MODE_LOW_BYTE: u8 = 0x31;

/// Product-class cooling topology (policy input — not a product SKU list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoolingBoardClass {
    /// S9-class: no C52 mux (am1 fan-control only).
    Am1S9,
    /// AM2 S17-class: four tach layout proven; C52 board-control rewrite **not**
    /// proven for this generation — preserve mode.
    Am2S17Preserve,
    /// AM2 S19-family: C52 write live-proven (`a lab unit` / S19j Pro class).
    Am2S19C52Required,
    /// Non-Zynq / serial / other — C52 register not applicable.
    NotApplicable,
}

/// Operator / image cooling posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoolingProfileKind {
    /// Residential / space-heater / quiet-first (default for home images).
    Home,
    /// Lab / industrial — may soft-prefer C52 without hard refuse.
    Lab,
}

/// Outcome of C52 custody admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C52CustodyDecision {
    /// No C52 requirement for this composition.
    NotRequired,
    /// C52 write preferred but missing is not an energize blocker (lab only).
    SoftPrefer,
    /// Home + AM2-S19: C52 receipt required before energize.
    Required,
}

/// Why C52 admission refused energize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum C52AdmissionError {
    /// Home profile on AM2-S19 without a successful C52 receipt.
    MissingRequiredReceipt { detail: String },
    /// Receipt present but low byte is not C52.
    ReadbackMismatch { observed_low: u8 },
}

impl std::fmt::Display for C52AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRequiredReceipt { detail } => {
                write!(f, "C52 fan-mode custody required but missing: {detail}")
            }
            Self::ReadbackMismatch { observed_low } => write!(
                f,
                "C52 fan-mode readback mismatch: expected 0x{C52_MODE_LOW_BYTE:02X}, observed 0x{observed_low:02X}"
            ),
        }
    }
}

impl std::error::Error for C52AdmissionError {}

/// Pure custody requirement from board class + profile.
pub fn c52_custody_decision(
    board: CoolingBoardClass,
    profile: CoolingProfileKind,
) -> C52CustodyDecision {
    match (board, profile) {
        (CoolingBoardClass::Am2S19C52Required, CoolingProfileKind::Home) => {
            C52CustodyDecision::Required
        }
        (CoolingBoardClass::Am2S19C52Required, CoolingProfileKind::Lab) => {
            C52CustodyDecision::SoftPrefer
        }
        (
            CoolingBoardClass::Am1S9
            | CoolingBoardClass::Am2S17Preserve
            | CoolingBoardClass::NotApplicable,
            _,
        ) => C52CustodyDecision::NotRequired,
    }
}

/// True when the low byte of board-control mode is C52.
pub const fn is_c52_mode_low_byte(low: u8) -> bool {
    low == C52_MODE_LOW_BYTE
}

/// Admit (or refuse) energize given a C52 requirement and optional receipt.
///
/// `receipt_low_byte` is `Some(low)` when the adapter observed a successful
/// mode write/readback; `None` means no receipt was produced.
pub fn admit_c52_custody(
    decision: C52CustodyDecision,
    receipt_low_byte: Option<u8>,
) -> Result<(), C52AdmissionError> {
    match decision {
        C52CustodyDecision::NotRequired => Ok(()),
        C52CustodyDecision::SoftPrefer => {
            // Lab: never refuse here; adapters log soft failure.
            Ok(())
        }
        C52CustodyDecision::Required => match receipt_low_byte {
            None => Err(C52AdmissionError::MissingRequiredReceipt {
                detail:
                    "home profile on AM2-S19 requires board-control C52 receipt before energize"
                        .into(),
            }),
            Some(low) if is_c52_mode_low_byte(low) => Ok(()),
            Some(low) => Err(C52AdmissionError::ReadbackMismatch { observed_low: low }),
        },
    }
}

/// Convenience: home AM2-S19 fail-closed admission.
pub fn admit_home_am2_s19_c52(receipt_low_byte: Option<u8>) -> Result<(), C52AdmissionError> {
    admit_c52_custody(
        c52_custody_decision(
            CoolingBoardClass::Am2S19C52Required,
            CoolingProfileKind::Home,
        ),
        receipt_low_byte,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_am2_s19_requires_c52() {
        assert_eq!(
            c52_custody_decision(
                CoolingBoardClass::Am2S19C52Required,
                CoolingProfileKind::Home
            ),
            C52CustodyDecision::Required
        );
    }

    #[test]
    fn lab_am2_s19_is_soft_prefer() {
        assert_eq!(
            c52_custody_decision(
                CoolingBoardClass::Am2S19C52Required,
                CoolingProfileKind::Lab
            ),
            C52CustodyDecision::SoftPrefer
        );
    }

    #[test]
    fn s17_and_s9_never_require_c52() {
        for board in [
            CoolingBoardClass::Am1S9,
            CoolingBoardClass::Am2S17Preserve,
            CoolingBoardClass::NotApplicable,
        ] {
            assert_eq!(
                c52_custody_decision(board, CoolingProfileKind::Home),
                C52CustodyDecision::NotRequired
            );
        }
    }

    #[test]
    fn home_missing_receipt_refuses() {
        let err = admit_home_am2_s19_c52(None).unwrap_err();
        assert!(matches!(
            err,
            C52AdmissionError::MissingRequiredReceipt { .. }
        ));
    }

    #[test]
    fn home_c49_readback_refuses() {
        let err = admit_home_am2_s19_c52(Some(C49_MODE_LOW_BYTE)).unwrap_err();
        assert_eq!(
            err,
            C52AdmissionError::ReadbackMismatch {
                observed_low: C49_MODE_LOW_BYTE
            }
        );
    }

    #[test]
    fn home_c52_receipt_admits() {
        assert!(admit_home_am2_s19_c52(Some(C52_MODE_LOW_BYTE)).is_ok());
    }

    #[test]
    fn lab_missing_receipt_does_not_refuse() {
        assert!(admit_c52_custody(C52CustodyDecision::SoftPrefer, None).is_ok());
    }

    #[test]
    fn constants_match_live_proven_bytes() {
        assert_eq!(C52_MODE_LOW_BYTE, 0x34);
        assert_eq!(C49_MODE_LOW_BYTE, 0x31);
    }
}
