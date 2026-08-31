use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PllExpectation {
    pub chip_id: u16,
    pub register: u8,
    pub reference_clock_mhz: u8,
    pub reset_value: Option<u32>,
    pub representative_frequency_mhz: Option<u16>,
    pub representative_value: Option<u32>,
    pub provenance: &'static str,
}

const MASTER: &str = "";

pub static PLL_EXPECTATIONS: &[PllExpectation] = &[
    PllExpectation { chip_id: 0x1387, register: 0x0c, reference_clock_mhz: 25, reset_value: None, representative_frequency_mhz: Some(650), representative_value: Some(0x0068_0221), provenance: MASTER },
    PllExpectation { chip_id: 0x1391, register: 0x0c, reference_clock_mhz: 25, reset_value: None, representative_frequency_mhz: None, representative_value: None, provenance: ":freq_pll_1385" },
    PllExpectation { chip_id: 0x1397, register: 0x08, reference_clock_mhz: 25, reset_value: Some(0xc060_0161), representative_frequency_mhz: Some(650), representative_value: None, provenance: MASTER },
    PllExpectation { chip_id: 0x1398, register: 0x08, reference_clock_mhz: 25, reset_value: Some(0xc060_0161), representative_frequency_mhz: Some(650), representative_value: None, provenance: MASTER },
    PllExpectation { chip_id: 0x1362, register: 0x08, reference_clock_mhz: 25, reset_value: None, representative_frequency_mhz: Some(545), representative_value: Some(0x50da_0141), provenance: MASTER },
    PllExpectation { chip_id: 0x1366, register: 0x08, reference_clock_mhz: 25, reset_value: None, representative_frequency_mhz: Some(670), representative_value: None, provenance: MASTER },
    PllExpectation { chip_id: 0x1368, register: 0x08, reference_clock_mhz: 25, reset_value: None, representative_frequency_mhz: Some(525), representative_value: None, provenance: MASTER },
    PllExpectation { chip_id: 0x1370, register: 0x08, reference_clock_mhz: 25, reset_value: None, representative_frequency_mhz: Some(525), representative_value: None, provenance: ":get_pllparam_divider@0x000cb644" },
    PllExpectation { chip_id: 0x1372, register: 0x08, reference_clock_mhz: 25, reset_value: None, representative_frequency_mhz: None, representative_value: None, provenance: "SCAFFOLD_NO_GROUND_TRUTH" },
];

pub fn pll_expectation(chip_id: u16) -> Option<&'static PllExpectation> {
    PLL_EXPECTATIONS
        .iter()
        .find(|expectation| expectation.chip_id == chip_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_are_unique_and_scaffold_provenance_is_explicit() {
        assert_eq!(PLL_EXPECTATIONS.len(), 9);
        for (index, row) in PLL_EXPECTATIONS.iter().enumerate() {
            assert!(PLL_EXPECTATIONS[..index]
                .iter()
                .all(|other| other.chip_id != row.chip_id));
            assert!(!row.provenance.trim().is_empty());
        }
        assert_eq!(
            pll_expectation(0x1372).map(|row| (
                row.reset_value,
                row.representative_frequency_mhz,
                row.representative_value,
                row.provenance,
            )),
            Some((None, None, None, "SCAFFOLD_NO_GROUND_TRUTH"))
        );
        assert!(PLL_EXPECTATIONS
            .iter()
            .filter(|row| row.chip_id != 0x1372)
            .all(|row| row.provenance != "SCAFFOLD_NO_GROUND_TRUTH"));
    }

    /// W8 CLK-4: the per-chip declared reference is uniformly 25 MHz today.
    /// This field is enforced against the production PLL solvers by
    /// `dcentrald_common::pll_model::PLL_REFERENCE_HZ` (compile-time pinned in
    /// the BM1362 driver, cross-pinned by
    /// `dcentrald-asic/tests/w8_clk4_pll_reference_crosspin.rs`). If a chip
    /// with a genuinely different XIN is RE'd, change this pin deliberately
    /// together with a fail-closed solver path — never by editing one side.
    #[test]
    fn every_declared_reference_clock_is_25_mhz_today() {
        for row in PLL_EXPECTATIONS {
            assert_eq!(
                row.reference_clock_mhz, 25,
                "chip {:#06x}: reference_clock_mhz drifted from the uniform 25 MHz corpus",
                row.chip_id
            );
        }
    }

    #[test]
    fn representative_known_values_are_pinned() {
        assert_eq!(
            pll_expectation(0x1387).and_then(|p| p.representative_value),
            Some(0x0068_0221)
        );
        assert_eq!(
            pll_expectation(0x1362).and_then(|p| p.representative_value),
            Some(0x50da_0141)
        );
        assert_eq!(
            pll_expectation(0x1372).and_then(|p| p.representative_value),
            None
        );
    }

    #[test]
    fn bm1368_s21_representative_frequency_is_the_proven_525() {
        // BM1368/S21 proven target is 525 MHz (S21 .135), matching the
        // model_catalog s21 row (Exact) and MASTER_PLL_REGISTER_BIBLE §6.1.
        // Regression pin for the prior 500 MHz transcription error.
        assert_eq!(
            pll_expectation(0x1368).and_then(|p| p.representative_frequency_mhz),
            Some(525)
        );
    }

    /// Every pll_bible representative frequency must be a REAL catalogued board
    /// operating point: it must equal the `default_frequency_mhz` of at least
    /// one `ModelEvidence` with the same chip_id. Catches cross-catalog drift
    /// like the BM1368/S21 500-vs-525 bug (500 matched no board). A chip with
    /// several boards at different freqs (BM1398: s19=650, s19pro=675) is fine
    /// as long as the representative matches ONE of them.
    #[test]
    fn representative_freq_matches_a_catalogued_board() {
        use crate::model_catalog::ANTMINER_MODELS;
        for p in PLL_EXPECTATIONS {
            if let Some(freq) = p.representative_frequency_mhz {
                let matches = ANTMINER_MODELS
                    .iter()
                    .any(|m| m.chip_id == p.chip_id && m.default_frequency_mhz == Some(freq));
                assert!(
                    matches,
                    "pll_bible chip_id {:#06x} representative_frequency_mhz={} matches no \
                     ANTMINER_MODELS board with that chip_id (a representative frequency must be \
                     a real catalogued board operating point)",
                    p.chip_id, freq
                );
            }
        }
    }
}
