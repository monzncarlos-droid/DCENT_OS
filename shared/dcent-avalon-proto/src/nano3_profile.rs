// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies - explicit Canaan Avalon Nano 3 (non-3S) profile.
//
// This profile is deliberately separate from `board`, which is the registry of
// held K210 industrial firmware images. A stock Nano 3 telemetry string that
// resembles an industrial silicon token is not sufficient evidence to project
// this K230 home miner into that registry. Nano 3S is also a separate target:
// its public architecture and held image do not establish the non-S UART
// contract captured here.
//
// The row carries identity and receive-side enumeration facts only. Resolving
// it grants neither native UART transmit authority nor mining authority.

use core::fmt;

/// Stable config key for the held non-S Nano 3 target.
pub const NANO3_MODEL_ID: &str = "nano3";

/// Linux chain UART opened by the held non-S stock `btcminer`.
pub const NANO3_CHAIN_UART: &str = "/dev/ttyS1";

/// Exact ASIC count required by the native receive/admission contract.
pub const NANO3_REQUIRED_ASIC_COUNT: u8 = 10;

/// Stock termios rate used for initial enumeration and the native UART link.
pub const NANO3_ENUMERATION_BAUD: u32 = 115_200;

/// Source for the identity facts in this row.
pub const NANO3_PROFILE_EVIDENCE: &str =
    "";

/// Every unresolved production requirement for the non-S profile.
///
/// These strings are intentionally operator-facing: `validate_for_mining`
/// includes all of them in one error instead of stopping at a vague
/// "descriptive-only" message.
pub const NANO3_MINING_BLOCKERS: [&str; 6] = [
    "independent normally-open whole-device hash-power cut with observed rail collapse",
    "compile-pinned exact power-chain qualification record with numeric cooling, heartbeat, cutoff, and coast-down limits",
    "complete native Nano 3 init/job contract plus externally protected TX validation",
    "exclusive cooling-actuator custody with fresh fan-tach feedback",
    "exclusive temperature-sensor custody with a stale/sensor-loss cut trip",
    "exclusive watchdog custody with verified expiry-to-cut behavior",
];

const NANO3_MINING_BLOCKERS_TEXT: &str =
    "independent normally-open whole-device hash-power cut with observed rail collapse; \
     compile-pinned exact power-chain qualification record with numeric cooling, heartbeat, cutoff, and coast-down limits; \
     complete native Nano 3 init/job contract plus externally protected TX validation; \
     exclusive cooling-actuator custody with fresh fan-tach feedback; \
     exclusive temperature-sensor custody with a stale/sensor-loss cut trip; \
     exclusive watchdog custody with verified expiry-to-cut behavior";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nano3Variant {
    /// The original Avalon Nano 3. This is not the Nano 3S.
    NonS,
}

impl fmt::Display for Nano3Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Nano 3 (non-3S)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nano3ControllerSoc {
    K230,
}

impl fmt::Display for Nano3ControllerSoc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("K230")
    }
}

/// Identity-only facts for the held Canaan Avalon Nano 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nano3TargetProfile {
    pub model_id: &'static str,
    pub product_name: &'static str,
    pub variant: Nano3Variant,
    pub controller_soc: Nano3ControllerSoc,
    pub linux_chain_uart: &'static str,
    pub required_observed_asic_count: u8,
    pub enumeration_baud: u32,
    pub evidence_path: &'static str,
}

pub const NANO3: Nano3TargetProfile = Nano3TargetProfile {
    model_id: NANO3_MODEL_ID,
    product_name: "Canaan Avalon Nano 3",
    variant: Nano3Variant::NonS,
    controller_soc: Nano3ControllerSoc::K230,
    linux_chain_uart: NANO3_CHAIN_UART,
    required_observed_asic_count: NANO3_REQUIRED_ASIC_COUNT,
    enumeration_baud: NANO3_ENUMERATION_BAUD,
    evidence_path: NANO3_PROFILE_EVIDENCE,
};

impl Nano3TargetProfile {
    /// Identity resolution never grants permission to transmit on the chain.
    pub const fn native_tx_authorized(&self) -> bool {
        false
    }

    /// Identity resolution never grants permission to energize or mine.
    pub const fn is_energizable(&self) -> bool {
        false
    }

    /// Fail closed while naming every missing production custody requirement.
    pub fn validate_for_mining(&self) -> Result<(), Nano3ProfileError> {
        Err(Nano3ProfileError::NotMiningReady {
            model_id: self.model_id,
            missing: NANO3_MINING_BLOCKERS_TEXT,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Nano3ProfileError {
    #[error(
        "Nano 3S target `{0}` is separate and unknown; non-S Nano 3 identity, UART, ASIC-count, or custody evidence must not be inherited"
    )]
    Nano3sIsSeparateUnknownTarget(String),

    #[error(
        "Nano 3 profile `{model_id}` is identity-only and authorizes neither mining nor native TX; missing: {missing}"
    )]
    NotMiningReady {
        model_id: &'static str,
        missing: &'static str,
    },
}

const NANO3_ALIASES: [&str; 5] = [
    "nano3",
    "nano-3",
    "nano 3",
    "avalon nano 3",
    "canaan avalon nano 3",
];

const NANO3S_ALIASES: [&str; 5] = [
    "nano3s",
    "nano-3s",
    "nano 3s",
    "avalon nano 3s",
    "canaan avalon nano 3s",
];

/// Resolve only Nano-family tokens.
///
/// `Ok(Some(..))` means the explicit non-S profile. `Ok(None)` means the token
/// is unrelated and may be offered to another registry. Nano 3S returns an
/// explicit error so a caller cannot silently treat it as the non-S device.
pub fn resolve(model: &str) -> Result<Option<&'static Nano3TargetProfile>, Nano3ProfileError> {
    let needle = model.trim();
    if NANO3_ALIASES
        .iter()
        .any(|alias| alias.eq_ignore_ascii_case(needle))
    {
        return Ok(Some(&NANO3));
    }
    if NANO3S_ALIASES
        .iter()
        .any(|alias| alias.eq_ignore_ascii_case(needle))
    {
        return Err(Nano3ProfileError::Nano3sIsSeparateUnknownTarget(
            model.to_owned(),
        ));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_pins_only_observed_non_s_identity_facts() {
        assert_eq!(NANO3.model_id, "nano3");
        assert_eq!(NANO3.variant, Nano3Variant::NonS);
        assert_eq!(NANO3.controller_soc, Nano3ControllerSoc::K230);
        assert_eq!(NANO3.linux_chain_uart, "/dev/ttyS1");
        assert_eq!(NANO3.required_observed_asic_count, 10);
        assert_eq!(NANO3.enumeration_baud, 115_200);
        assert!(NANO3
            .evidence_path
            .ends_with("NANO3_NATIVE_UART_PROTOCOL_RE.md"));
    }

    #[test]
    fn non_s_aliases_resolve_but_nano3s_is_explicitly_separate() {
        for alias in NANO3_ALIASES {
            assert_eq!(resolve(alias).unwrap(), Some(&NANO3), "{alias}");
            assert_eq!(
                resolve(&alias.to_uppercase()).unwrap(),
                Some(&NANO3),
                "{alias}"
            );
        }
        for alias in NANO3S_ALIASES {
            let err = resolve(alias).expect_err("Nano 3S must never inherit Nano 3");
            assert!(matches!(
                err,
                Nano3ProfileError::Nano3sIsSeparateUnknownTarget(_)
            ));
            assert!(err.to_string().contains("separate and unknown"));
        }
        assert_eq!(resolve("a14x").unwrap(), None);
    }

    #[test]
    fn identity_grants_neither_native_tx_nor_mining() {
        assert!(!NANO3.native_tx_authorized());
        assert!(!NANO3.is_energizable());

        let err = NANO3
            .validate_for_mining()
            .expect_err("identity must not become mining authority")
            .to_string();
        assert!(err.contains("authorizes neither mining nor native TX"));
        for blocker in NANO3_MINING_BLOCKERS {
            assert!(err.contains(blocker), "missing blocker in error: {blocker}");
        }
    }
}
