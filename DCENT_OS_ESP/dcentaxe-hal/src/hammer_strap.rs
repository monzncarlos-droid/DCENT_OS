// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure Hammer DC TMP75 identity-strap classification.
//!
//! The strap is identity metadata only. Nothing in this module reads a
//! temperature register or makes the device a trusted thermal source.

/// Every address used by the registered DC02/DC04/DC06 straps or the
/// unregistered DC08 dual-board signature. Probe only on an already-resolved
/// Hammer DC model: several addresses belong to unrelated devices elsewhere.
pub const HAMMER_STRAP_ADDRS: [u8; 5] = [0x48, 0x4A, 0x4C, 0x4E, 0x4F];

/// Verdict from the read-only address-only ACK scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HammerStrapProbeVerdict {
    /// Exactly the registered row's address ACKed.
    Match,
    /// No candidate strap address ACKed.
    Absent,
    /// Another address, or more than one address, ACKed.
    Mismatch { observed_mask: u8 },
}

/// Stable bit for one candidate address, or zero for a non-candidate.
pub const fn hammer_strap_addr_bit(addr: u8) -> u8 {
    match addr {
        0x48 => 1 << 0,
        0x4A => 1 << 1,
        0x4C => 1 << 2,
        0x4E => 1 << 3,
        0x4F => 1 << 4,
        _ => 0,
    }
}

/// Classify a candidate-address ACK mask against the registered row.
///
/// A match is deliberately strict: a DC08 signature (0x4A + 0x4E), a second
/// responding candidate, and an unsupported expected address all refuse.
pub const fn classify_hammer_strap_probe(
    expected_addr: u8,
    observed_mask: u8,
) -> HammerStrapProbeVerdict {
    if observed_mask == 0 {
        HammerStrapProbeVerdict::Absent
    } else {
        let expected_bit = hammer_strap_addr_bit(expected_addr);
        if expected_bit != 0 && observed_mask == expected_bit {
            HammerStrapProbeVerdict::Match
        } else {
            HammerStrapProbeVerdict::Mismatch { observed_mask }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hammer_strap_classifier_truth_table_includes_dc08_refusal() {
        for expected in [0x48, 0x4C, 0x4F] {
            assert_eq!(
                classify_hammer_strap_probe(expected, hammer_strap_addr_bit(expected)),
                HammerStrapProbeVerdict::Match
            );
            assert_eq!(
                classify_hammer_strap_probe(expected, 0),
                HammerStrapProbeVerdict::Absent
            );
        }

        let dc08 = hammer_strap_addr_bit(0x4A) | hammer_strap_addr_bit(0x4E);
        assert_eq!(
            classify_hammer_strap_probe(0x4C, dc08),
            HammerStrapProbeVerdict::Mismatch {
                observed_mask: dc08
            },
            "unregistered DC08 must never be mis-adopted as DC04"
        );
        assert!(matches!(
            classify_hammer_strap_probe(0x48, hammer_strap_addr_bit(0x4C)),
            HammerStrapProbeVerdict::Mismatch { .. }
        ));
        assert!(matches!(
            classify_hammer_strap_probe(0x49, hammer_strap_addr_bit(0x49)),
            HammerStrapProbeVerdict::Absent
        ));
    }
}
