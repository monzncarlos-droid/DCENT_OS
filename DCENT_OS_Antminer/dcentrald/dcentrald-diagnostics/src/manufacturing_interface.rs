//! Canonical manufacturing-interface capability ceiling.
//!
//! The implemented manufacturing surface is the default-OFF, host-pure factory
//! pattern parser/grader in `pattern_test`.  This module remains available in
//! default builds so source inventory never mistakes a feature-gated parser for
//! a live factory-test engine.

/// Exact manufacturing interface represented in the source tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManufacturingInterface {
    Bm1362Wide48Pattern,
    Bm1366Wide48Pattern,
    Bm1368Compact12Pattern,
}

/// Maximum implementation state for a manufacturing interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManufacturingInterfaceCapabilityState {
    /// Held format and grading constants feed a feature-gated, offline parser;
    /// no pattern work is dispatched and no hardware verdict is minted.
    HeldOfflinePatternParserFeatureGated,
}

/// Non-authorizing capability record for one exact factory-pattern family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManufacturingInterfaceCapability {
    pub interface: ManufacturingInterface,
    pub state: ManufacturingInterfaceCapabilityState,
    pub family: &'static str,
    pub record_format: &'static str,
    pub offline_parser_feature: &'static str,
    pub held_record_geometry_verified: bool,
    pub nonce_semantics_decompile_verified: bool,
    pub held_grading_constants_verified: bool,
    pub live_pattern_dispatch_authorized: bool,
    pub voltage_target_authorized: bool,
    pub manufacturing_pass_authorized: bool,
    pub hardware_mutation_authorized: bool,
}

/// Exhaustive manufacturing-interface registry for dcentrald diagnostics.
pub const MANUFACTURING_INTERFACE_CAPABILITIES: &[ManufacturingInterfaceCapability] = &[
    ManufacturingInterfaceCapability {
        interface: ManufacturingInterface::Bm1362Wide48Pattern,
        state: ManufacturingInterfaceCapabilityState::HeldOfflinePatternParserFeatureGated,
        family: "BM1362",
        record_format: "Wide48",
        offline_parser_feature: "pattern-selftest",
        held_record_geometry_verified: true,
        nonce_semantics_decompile_verified: false,
        held_grading_constants_verified: true,
        live_pattern_dispatch_authorized: false,
        voltage_target_authorized: false,
        manufacturing_pass_authorized: false,
        hardware_mutation_authorized: false,
    },
    ManufacturingInterfaceCapability {
        interface: ManufacturingInterface::Bm1366Wide48Pattern,
        state: ManufacturingInterfaceCapabilityState::HeldOfflinePatternParserFeatureGated,
        family: "BM1366",
        record_format: "Wide48",
        offline_parser_feature: "pattern-selftest",
        held_record_geometry_verified: true,
        nonce_semantics_decompile_verified: false,
        held_grading_constants_verified: true,
        live_pattern_dispatch_authorized: false,
        voltage_target_authorized: false,
        manufacturing_pass_authorized: false,
        hardware_mutation_authorized: false,
    },
    ManufacturingInterfaceCapability {
        interface: ManufacturingInterface::Bm1368Compact12Pattern,
        state: ManufacturingInterfaceCapabilityState::HeldOfflinePatternParserFeatureGated,
        family: "BM1368",
        record_format: "Compact12",
        offline_parser_feature: "pattern-selftest",
        held_record_geometry_verified: true,
        nonce_semantics_decompile_verified: true,
        held_grading_constants_verified: true,
        live_pattern_dispatch_authorized: false,
        voltage_target_authorized: false,
        manufacturing_pass_authorized: false,
        hardware_mutation_authorized: false,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manufacturing_interface_registry_is_exhaustive_and_non_authorizing() {
        let all_interfaces = [
            ManufacturingInterface::Bm1362Wide48Pattern,
            ManufacturingInterface::Bm1366Wide48Pattern,
            ManufacturingInterface::Bm1368Compact12Pattern,
        ];
        assert_eq!(
            MANUFACTURING_INTERFACE_CAPABILITIES.len(),
            all_interfaces.len()
        );
        for interface in all_interfaces {
            let matches: Vec<_> = MANUFACTURING_INTERFACE_CAPABILITIES
                .iter()
                .filter(|capability| capability.interface == interface)
                .collect();
            assert_eq!(matches.len(), 1);
            let capability = matches[0];
            assert_eq!(
                capability.state,
                ManufacturingInterfaceCapabilityState::HeldOfflinePatternParserFeatureGated
            );
            assert!(capability.held_record_geometry_verified);
            assert_eq!(
                capability.nonce_semantics_decompile_verified,
                interface == ManufacturingInterface::Bm1368Compact12Pattern
            );
            assert!(capability.held_grading_constants_verified);
            assert!(!capability.live_pattern_dispatch_authorized);
            assert!(!capability.voltage_target_authorized);
            assert!(!capability.manufacturing_pass_authorized);
            assert!(!capability.hardware_mutation_authorized);
        }
    }

    #[cfg(feature = "pattern-selftest")]
    #[test]
    fn registry_matches_feature_gated_pattern_standards() {
        use crate::pattern_test::{family_test_standard, PatternFormat, FAMILY_TEST_STANDARDS};

        assert_eq!(
            MANUFACTURING_INTERFACE_CAPABILITIES.len(),
            FAMILY_TEST_STANDARDS.len()
        );
        for capability in MANUFACTURING_INTERFACE_CAPABILITIES {
            let standard = family_test_standard(capability.family)
                .expect("every capability family must have an exact grading standard");
            let format_name = match standard.format {
                PatternFormat::Compact12 => "Compact12",
                PatternFormat::Wide48 => "Wide48",
            };
            assert_eq!(capability.record_format, format_name);
        }
    }
}
