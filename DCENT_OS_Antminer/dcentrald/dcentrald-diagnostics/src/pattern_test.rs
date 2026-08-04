//! Factory pattern-test grading — OFFLINE parser + grader (Hardware-Enablement item U9).
//!
//! Bitmain's AMTC factory single-board-test flashes each ASIC with a fixed set of
//! "pattern" work items whose golden nonces are known, then counts how many each core
//! returns and grades the chip. This module supplies the **offline** half of that
//! capability: it parses the held factory pattern `.bin` files and grades a per-core
//! returned-nonce map against the factory `Test_Standard`. It performs **no hardware
//! I/O and dispatches no work** — the live self-test arm (which would dispatch these
//! patterns to real chips) is deliberately NOT here; that arm must consume the
//! `admit_work_dispatch` admission gate and is a separate, gated item.
//!
//! Opt-in: this module is compiled only under the default-OFF `pattern-selftest`
//! feature.
//!
//! # Provenance
//!
//! Record formats (jig-decompiled / whole-file-empirical), sourced 2026-07-25:
//! - **Compact 12-byte** (BM1368 / S21): decompile-proven from the AMTC S21 jig
//!   `single_board_test.dec` — `parse_bin_file_16midstate_sf@B546C.c`
//!   (`fread(&work, 1, 12, fp)`, `nonce = ntohl(bytes[0..4])`) and the writer
//!   `transform_txt_to_bin@BDBB8.c` (`struct { u32 nonce; u8 midstate[8]; }`, nonce
//!   stored big-endian via `htonl`). Record order is `[asic][core][pattern]`, 8 rows
//!   per core (`parse_bin_file_to_pattern_ex@B51B8.c` + `skip_rows@B5108.c`), and
//!   `108 asic x 1280 core x 8 pattern = 1,105,920 = 13,271,040/12` exactly.
//! - **Wide 48-byte** (BM1362 / BM1366 — S19j Pro / S19k jigs, which have no `.dec`):
//!   whole-file-empirical — midstate at `[4:36]` (constant across the file), a
//!   constant word `26 f5 fe 65` at `[36:40]`, the golden nonce at `[40:44]`, and
//!   `[44:48]` zero in the main pools. The 48-byte nonce **endianness is not
//!   decompile-confirmed**; treat Wide48 nonce extraction as high-confidence-empirical.
//!
//! `Test_Standard` grading constants per family come from the held factory
//! `Config.ini` (see [`FAMILY_TEST_STANDARDS`]). They deliberately carry **no voltage
//! field**: the fixtures' `Pre_Open_Core_Voltage`/`Voltage` are fixture-only evidence
//! and must never become production cold-boot targets (2026-04-25 rule).
//!
//! Pure, host-testable, no HAL/IO, panic-free in non-test code.

/// On-disk record layout of a factory pattern `.bin`, keyed by jig generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternFormat {
    /// BM1368 / S21: 12-byte records `{u32 nonce (big-endian); u8 midstate[8]}`.
    Compact12,
    /// BM1362 / BM1366: 48-byte records; golden nonce at byte offset 40.
    Wide48,
}

impl PatternFormat {
    /// Fixed record stride in bytes.
    pub const fn stride(self) -> usize {
        match self {
            Self::Compact12 => 12,
            Self::Wide48 => 48,
        }
    }

    /// Byte offset of the 4-byte big-endian golden nonce within a record.
    const fn nonce_offset(self) -> usize {
        match self {
            Self::Compact12 => 0,
            Self::Wide48 => 40,
        }
    }

    /// Select the on-disk format from the ASIC family string (proven mapping).
    pub fn for_family(family: &str) -> Self {
        match family.trim() {
            "BM1362" | "BM1366" => Self::Wide48,
            _ => Self::Compact12,
        }
    }
}

/// Pattern-file parse failure. Every variant is a fail-closed refusal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    /// The blob is empty.
    #[error("pattern file is empty")]
    Empty,
    /// The blob length is not a whole number of `stride`-byte records.
    #[error("pattern file length {len} is not a whole number of {stride}-byte records")]
    BadLength { len: usize, stride: usize },
}

/// A source of factory pattern records (their golden nonces).
pub trait PatternSource {
    /// On-disk record format.
    fn format(&self) -> PatternFormat;
    /// Number of records available.
    fn record_count(&self) -> usize;
    /// Big-endian golden nonce for record `index`, or `None` if out of range.
    fn golden_nonce_be(&self, index: usize) -> Option<u32>;
}

/// Zero-copy reader over a real factory pattern `.bin` blob.
pub struct FactoryPatternFile<'a> {
    format: PatternFormat,
    data: &'a [u8],
}

impl<'a> FactoryPatternFile<'a> {
    /// Open a pattern blob, validating the universal invariant `len % stride == 0`.
    /// This is the always-safe offline check (the exact `asic x core x pattern`
    /// factorization only holds for a board-specific compact file; the wide pools are
    /// generic record pools).
    pub fn open(data: &'a [u8], format: PatternFormat) -> Result<Self, PatternError> {
        if data.is_empty() {
            return Err(PatternError::Empty);
        }
        let stride = format.stride();
        if data.len() % stride != 0 {
            return Err(PatternError::BadLength {
                len: data.len(),
                stride,
            });
        }
        Ok(Self { format, data })
    }

    /// Total blob length in bytes.
    pub fn len_bytes(&self) -> usize {
        self.data.len()
    }
}

impl PatternSource for FactoryPatternFile<'_> {
    fn format(&self) -> PatternFormat {
        self.format
    }

    fn record_count(&self) -> usize {
        self.data.len() / self.format.stride()
    }

    fn golden_nonce_be(&self, index: usize) -> Option<u32> {
        let stride = self.format.stride();
        let start = index
            .checked_mul(stride)?
            .checked_add(self.format.nonce_offset())?;
        let bytes: [u8; 4] = self
            .data
            .get(start..start.checked_add(4)?)?
            .try_into()
            .ok()?;
        Some(u32::from_be_bytes(bytes))
    }
}

/// A deterministic **synthetic** Compact12 pattern source, for exercising the
/// parse/grade pipeline with **no held asset and no miner**. The nonces are a
/// reproducible sequence — this is NOT a factory pattern, only a self-test fixture.
pub struct SyntheticDiff1Pattern {
    nonces: Vec<u32>,
}

impl SyntheticDiff1Pattern {
    /// Build `count` deterministic synthetic records (no RNG — reproducible).
    pub fn new(count: usize) -> Self {
        let nonces = (0..count)
            .map(|i| 0x1000_0000u32.wrapping_add((i as u32).wrapping_mul(0x9E37_79B1)))
            .collect();
        Self { nonces }
    }
}

impl PatternSource for SyntheticDiff1Pattern {
    fn format(&self) -> PatternFormat {
        PatternFormat::Compact12
    }

    fn record_count(&self) -> usize {
        self.nonces.len()
    }

    fn golden_nonce_be(&self, index: usize) -> Option<u32> {
        self.nonces.get(index).copied()
    }
}

/// Per-family factory grading standard (from the held AMTC `Config.ini`). No voltage
/// field by design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FamilyTestStandard {
    pub family: &'static str,
    pub format: PatternFormat,
    pub asic_num: u16,
    pub midstate_number: u8,
    pub pattern_number: u8,
    /// Minimum nonces a core must return to be graded good.
    pub least_nonce_per_core: u16,
    /// Factory `Invalid_Core_Number` tolerance (exposed as data; the exact chip
    /// verdict formula is not decompiled — grade at the core level, not by asserting
    /// a chip verdict from this alone).
    pub invalid_core_number: u16,
    /// Factory `Most_HW_Num` hardware-error ceiling (exposed as data).
    pub most_hw_num: u16,
}

/// The three families with held factory `Config.ini` evidence. Line citations are to
/// the fixture `Config.ini` alongside each pattern `.bin`.
pub const FAMILY_TEST_STANDARDS: &[FamilyTestStandard] = &[
    //  (Asic_Num L9, Midstate L55,
    // Test_Standard: Pattern L72, Invalid_Core L73, Least_Nonce L74, Most_HW L76).
    FamilyTestStandard {
        family: "BM1368",
        format: PatternFormat::Compact12,
        asic_num: 108,
        midstate_number: 16,
        pattern_number: 8,
        least_nonce_per_core: 6,
        invalid_core_number: 127,
        most_hw_num: 128,
    },
    //  (Asic_Type/Num L8-9,
    // Midstate L44, Pattern L49, Invalid_Core L50, Least_Nonce L51, Most_HW L53).
    FamilyTestStandard {
        family: "BM1362",
        format: PatternFormat::Wide48,
        asic_num: 126,
        midstate_number: 8,
        pattern_number: 8,
        least_nonce_per_core: 6,
        invalid_core_number: 77,
        most_hw_num: 128,
    },
    //  (Asic_Type/Num L8-9,
    // Midstate L55, Pattern L72, Invalid_Core L73, Least_Nonce L74, Most_HW L77).
    FamilyTestStandard {
        family: "BM1366",
        format: PatternFormat::Wide48,
        asic_num: 77,
        midstate_number: 8,
        pattern_number: 8,
        least_nonce_per_core: 6,
        invalid_core_number: 77,
        most_hw_num: 128,
    },
];

/// Look up the factory grading standard for an ASIC family.
pub fn family_test_standard(family: &str) -> Option<&'static FamilyTestStandard> {
    FAMILY_TEST_STANDARDS
        .iter()
        .find(|s| s.family.eq_ignore_ascii_case(family.trim()))
}

/// Whether a single core passes: it returned at least `least_nonce_per_core` nonces.
/// This is the decompile-proven core-level threshold.
pub fn core_passes(nonces_returned: u16, std: &FamilyTestStandard) -> bool {
    nonces_returned >= std.least_nonce_per_core
}

/// Count the bad cores (returned fewer than `least_nonce_per_core` nonces) in a chip's
/// per-core returned-nonce map. Pure tally — no chip verdict is asserted here (the
/// exact factory chip-pass formula over `invalid_core_number`/`most_hw_num` is not
/// decompiled; expose the tally + the standard and let the caller decide).
pub fn count_bad_cores(per_core_nonce_counts: &[u16], std: &FamilyTestStandard) -> usize {
    per_core_nonce_counts
        .iter()
        .filter(|&&n| !core_passes(n, std))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// First 96 bytes (8 records) of the real held BM1368 pattern file
    ///
    /// — embedded as a fixture so the KAT runs with no gitignored asset.
    const S21_BM1368_FIRST_96: [u8; 96] = [
        0x6a, 0x1c, 0x6e, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, // rec0
        0x59, 0x38, 0xdd, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5d, // rec1
        0xb0, 0x8d, 0x27, 0x5f, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77, // rec2
        0x19, 0x24, 0x93, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x7d, // rec3
        0x43, 0x21, 0xca, 0xd7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x39, // rec4
        0x6c, 0xe0, 0xdc, 0x1b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x22, // rec5
        0x45, 0x37, 0xd3, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x7d, // rec6
        0x65, 0xb8, 0xef, 0xee, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x03, 0x42, // rec7
    ];

    #[test]
    fn compact12_kat_matches_real_bm1368_pattern_file() {
        let f = FactoryPatternFile::open(&S21_BM1368_FIRST_96, PatternFormat::Compact12)
            .expect("valid 96-byte fixture");
        assert_eq!(f.record_count(), 8);
        // Golden nonces are the big-endian first 4 bytes of each 12-byte record —
        // pinned against the real held factory pattern file.
        let expected = [
            0x6a1c_6e23u32,
            0x5938_dd48,
            0xb08d_275f,
            0x1924_93fe,
            0x4321_cad7,
            0x6ce0_dc1b,
            0x4537_d3ac,
            0x65b8_efee,
        ];
        for (i, want) in expected.iter().enumerate() {
            assert_eq!(f.golden_nonce_be(i), Some(*want), "record {i}");
        }
        assert_eq!(f.golden_nonce_be(8), None, "no 9th record");
    }

    #[test]
    fn open_enforces_stride_invariant() {
        assert_eq!(
            FactoryPatternFile::open(&[], PatternFormat::Compact12).err(),
            Some(PatternError::Empty)
        );
        // 13 bytes is not a whole number of 12-byte records.
        assert_eq!(
            FactoryPatternFile::open(&[0u8; 13], PatternFormat::Compact12).err(),
            Some(PatternError::BadLength {
                len: 13,
                stride: 12
            })
        );
        // 47 bytes is not a whole number of 48-byte records.
        assert_eq!(
            FactoryPatternFile::open(&[0u8; 47], PatternFormat::Wide48).err(),
            Some(PatternError::BadLength {
                len: 47,
                stride: 48
            })
        );
        // Exact multiples open.
        assert_eq!(
            FactoryPatternFile::open(&[0u8; 96], PatternFormat::Wide48).map(|f| f.record_count()),
            Ok(2)
        );
    }

    #[test]
    fn real_file_lengths_divide_evenly_by_their_stride() {
        // The universal offline invariant, from the held file sizes.
        assert_eq!(13_271_040 % PatternFormat::Compact12.stride(), 0); // BM1368
        assert_eq!(24_869_376 % PatternFormat::Wide48.stride(), 0); // BM1362
        assert_eq!(43_255_296 % PatternFormat::Wide48.stride(), 0); // BM1366
                                                                    // Decompile-proven exact factorization for the board-specific compact file.
        assert_eq!(
            108usize * 1280 * 8 * PatternFormat::Compact12.stride(),
            13_271_040
        );
    }

    #[test]
    fn family_standards_are_sourced_and_carry_no_voltage() {
        let bm1368 = family_test_standard("bm1368").expect("BM1368 standard");
        assert_eq!(bm1368.format, PatternFormat::Compact12);
        assert_eq!(
            (
                bm1368.asic_num,
                bm1368.midstate_number,
                bm1368.pattern_number
            ),
            (108, 16, 8)
        );
        assert_eq!(
            (
                bm1368.least_nonce_per_core,
                bm1368.invalid_core_number,
                bm1368.most_hw_num
            ),
            (6, 127, 128)
        );
        assert_eq!(
            family_test_standard("BM1362").map(|s| s.format),
            Some(PatternFormat::Wide48)
        );
        assert_eq!(family_test_standard("BM1366").map(|s| s.asic_num), Some(77));
        assert_eq!(family_test_standard("BM9999"), None);
        assert_eq!(
            PatternFormat::for_family("BM1368"),
            PatternFormat::Compact12
        );
        assert_eq!(PatternFormat::for_family("BM1362"), PatternFormat::Wide48);
    }

    #[test]
    fn grader_uses_least_nonce_per_core_threshold() {
        let std = family_test_standard("BM1368").expect("standard");
        // least_nonce_per_core = 6: a 5-nonce core FAILS, a 6-nonce core PASSES.
        assert!(!core_passes(5, std));
        assert!(core_passes(6, std));
        assert!(core_passes(9977, std));
        assert!(!core_passes(0, std));
        // A synthetic per-core map: two cores below threshold, three at/above.
        let per_core = [6u16, 5, 8, 0, 6];
        assert_eq!(count_bad_cores(&per_core, std), 2);
        // All-good map has zero bad cores.
        assert_eq!(count_bad_cores(&[6u16; 100], std), 0);
    }

    #[test]
    fn synthetic_source_exercises_pipeline_without_a_held_asset() {
        let src = SyntheticDiff1Pattern::new(64);
        assert_eq!(src.format(), PatternFormat::Compact12);
        assert_eq!(src.record_count(), 64);
        // Deterministic + reproducible: same index -> same nonce, distinct across records.
        assert_eq!(
            src.golden_nonce_be(0),
            SyntheticDiff1Pattern::new(1).golden_nonce_be(0)
        );
        assert_ne!(src.golden_nonce_be(0), src.golden_nonce_be(1));
        assert_eq!(src.golden_nonce_be(64), None);
    }
}
