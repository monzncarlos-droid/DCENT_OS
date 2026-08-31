// SPDX-License-Identifier: GPL-3.0-or-later
// D-Central Technologies — Canaan Avalon industrial board registry.
//
// # What this is
//
// A DECLARATIVE registry of the Canaan Avalon industrial SKUs we hold firmware
// bytes for: 8 SKUs across 3 silicon families. It follows the pattern the ESP
// line already uses (`dcentaxe-hal/src/board.rs`'s `BoardVersionProfile::ALL`)
// and the pattern `dcent-avalon-a3197s` uses for its BENCH-CONFIRM table
// (`bench_confirm::REGISTRY`): one `const` array of rows, every row carrying its
// own provenance, resolution fail-closed on anything not in the table.
//
// Before this file there was NO board/model registry anywhere in the Avalon
// tree — no enum, no table (H8 §1.2, §4 item #6). Model identity lived only in
// prose and in firmware-archive filenames.
//
// # What this is NOT — read before using it
//
// **This registry describes hardware. It does not authorize energizing any of
// it.** Every row's frequency envelope, core-voltage envelope and tuning-preset
// list is `Evidence::Unknown`, and that is not an oversight: all 8 held images
// are AES-CBC-encrypted K210 boot images whose key is fused into the K210 OTP
// eFuse and is not present in any archive we hold
// (`AVALON_INDUSTRIAL_FW_RE.md` §1, §3). We have never seen a plaintext Avalon
// frequency table, voltage table or tuning preset. Inventing one would be
// exactly the class of guess that `dcent-avalon-a3197s`'s BENCH_CONFIRM gate
// exists to prevent, so `chain_parameters()` fails closed on every row and
// `is_energizable()` is false for every row — asserted by tests below.
//
// Adding a row to this table must never make a board energizable. If a future
// session bench-captures a real envelope, it goes in as `Evidence::Confirmed`
// with its capture cited, and the `no_registry_row_is_energizable` test becomes
// the deliberate thing that has to be updated with the operator's knowledge.
//
// # Evidence
//
// Every row is grounded in bytes on disk:
//   *.zip   (8 stock AUPs)
//   */           (8 extracted trees)
//    (the RE writeup)
//
// Confidence tags mirror that RE document's own legend verbatim, so a reader can
// walk a value straight back to its source line:
//   [C] confirmed by file content · [D] derived from public Canaan source
//   [L] likely / inferred          · [?] open question / no evidence

use core::fmt;

// ── Provenance ───────────────────────────────────────────────────────────────

/// A value together with how strongly we actually know it.
///
/// The point of the type is that `Derived` / `Likely` values can be *read and
/// displayed* but can never be mistaken for measurement: only
/// [`Evidence::confirmed`] hands back a value, and only the `Confirmed` variant
/// answers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence<T> {
    /// `[C]` — confirmed by bytes we hold and opened.
    Confirmed {
        value: T,
        /// Where the bytes are, precisely enough to re-check.
        source: &'static str,
    },
    /// `[D]` — derived from public third-party source we read but did not measure.
    Derived { value: T, source: &'static str },
    /// `[L]` — inferred from held evidence, not directly stated by it.
    Likely { value: T, source: &'static str },
    /// `[?]` — we have no evidence. Carries WHY, so the gap is legible rather
    /// than looking like a forgotten field.
    Unknown { why: &'static str },
}

impl<T> Evidence<T> {
    /// The RE-document confidence tag for this value.
    pub const fn tag(&self) -> &'static str {
        match self {
            Evidence::Confirmed { .. } => "[C]",
            Evidence::Derived { .. } => "[D]",
            Evidence::Likely { .. } => "[L]",
            Evidence::Unknown { .. } => "[?]",
        }
    }

    /// The value ONLY if it is confirmed by bytes we hold. Derived / likely /
    /// unknown all answer `None` — a caller that needs a measured number cannot
    /// accidentally consume an inference.
    pub const fn confirmed(&self) -> Option<&T> {
        match self {
            Evidence::Confirmed { value, .. } => Some(value),
            _ => None,
        }
    }

    /// The value at ANY confidence, for display / reporting only. Never use the
    /// result to drive hardware.
    pub const fn any(&self) -> Option<&T> {
        match self {
            Evidence::Confirmed { value, .. }
            | Evidence::Derived { value, .. }
            | Evidence::Likely { value, .. } => Some(value),
            Evidence::Unknown { .. } => None,
        }
    }

    /// Why the value is absent, for `Unknown` only.
    pub const fn why_unknown(&self) -> Option<&'static str> {
        match self {
            Evidence::Unknown { why } => Some(*why),
            _ => None,
        }
    }

    pub const fn is_unknown(&self) -> bool {
        matches!(self, Evidence::Unknown { .. })
    }
}

// ── Taxonomy ─────────────────────────────────────────────────────────────────

/// Canaan SHA-256 silicon families present in the held industrial firmware set.
///
/// Three families, taken from the `-A3xxx-` token that Canaan puts in every AUP
/// archive name and that `_summary.json`'s `asic_chip` records. `[C]`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvalonSilicon {
    /// A3200 die rev. C+. `AVALON_ARCHITECTURE.md` calls the A1346 part
    /// "A3200CFA"; the firmware filenames say "A3200C-Plus". Recorded here under
    /// the filename spelling because that is the token we hold. Not adjudicated.
    A3200CPlus,
    A3198S,
    A3197S,
}

impl AvalonSilicon {
    pub const ALL: [AvalonSilicon; 3] = [
        AvalonSilicon::A3200CPlus,
        AvalonSilicon::A3198S,
        AvalonSilicon::A3197S,
    ];

    /// The exact token used in the held AUP archive names.
    pub const fn archive_token(&self) -> &'static str {
        match self {
            AvalonSilicon::A3200CPlus => "A3200C-Plus",
            AvalonSilicon::A3198S => "A3198S",
            AvalonSilicon::A3197S => "A3197S",
        }
    }
}

impl fmt::Display for AvalonSilicon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.archive_token())
    }
}

/// The controller SoC the stock firmware runs on.
///
/// Every row in this table is K210 (RV64GC, FreeRTOS, 8 MB on-chip SRAM, no
/// external DDR) — that is what an AUP-v2-wrapped, `aes_enable`-flagged K210
/// SPI-flash boot image *is*. `[C]`. K230-based industrial SKUs (Avalon Q, A16x)
/// are deliberately absent: we hold no firmware for them, so they get no row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerSoc {
    K210,
}

/// Cooling class as far as the held bytes actually establish it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoolingClass {
    /// `Temp7x` filename token + a non-`_LC` `hw_list` tag. `[C]`
    AirCooled,
    /// `_LC` `hw_list` tag. **Ambiguous on purpose.** Our own extraction records
    /// this class as "liquid-cooled or hyper-power", and `AVALON_INDUSTRIAL_FW_RE.md`
    /// §4.2 shows `MM4v1_X3_LC` shared between the immersion-cooled `A14xI` and
    /// the hyper-power `A1466HS_MPO5000` — same controller PCB, different thermal
    /// product. Collapsing this to "liquid-cooled" would assert something the
    /// bytes do not say, so the ambiguity is carried in the type. `[C]` that it
    /// is one of the two; `[?]` which.
    LiquidOrHyperPowerUnresolved,
}

/// Frequency envelope in MHz. **No row in this registry populates one.**
/// The type exists so a bench-captured envelope has a typed seam to land in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreqEnvelopeMhz {
    pub min: u16,
    pub max: u16,
    pub default: u16,
}

/// Core-voltage envelope in millivolts. **No row in this registry populates
/// one.** Voltage is a safety parameter; see the module header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreVoltageEnvelopeMv {
    pub min: u16,
    pub max: u16,
    pub default: u16,
}

/// A named frequency/voltage operating point. **No row in this registry
/// populates one** — `tuning_presets` is empty everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TuningPreset {
    pub name: &'static str,
    pub freq_mhz: u16,
    pub core_mv: u16,
    /// Where this operating point was captured and proven.
    pub source: &'static str,
}

// ── The row ──────────────────────────────────────────────────────────────────

/// One Canaan Avalon industrial SKU, as established by firmware bytes we hold.
#[derive(Debug, Clone, Copy)]
pub struct AvalonBoardProfile {
    /// Lowercase stable key, matching the
    /// avalon-industrial/<dir>` name and `_summary.json`'s `model`. `[C]`
    pub model_id: &'static str,
    /// The product token exactly as Canaan writes it in the AUP archive name.
    /// Two rows name two products (`A1466HS_A14x`, `A1566HS_A15xI`) because
    /// Canaan ships one image for both. `[C]`
    pub product_token: &'static str,
    pub silicon: AvalonSilicon,
    pub controller_soc: ControllerSoc,
    /// AUP header `hw_list` entry — the on-device updater's hardware
    /// compatibility gate (MM controller-board generation). `[C]`
    pub mm_hw_tag: &'static str,
    /// AUP header `sw_list` entries — the software compatibility gate. `[C]`
    pub mm_sw_tags: &'static [&'static str],
    pub cooling: CoolingClass,
    /// The thermal / power token from the archive name (`Temp75`, `Temp70`,
    /// `LC`, `Temp70_MPO5000`). Recorded raw; not interpreted. `[C]`
    pub thermal_token: &'static str,
    /// AUP header `firmware_ver`. `[C]`
    pub firmware_ver: &'static str,
    /// AUP container format version. `2` for all 8. `[C]`
    pub aup_fmt_ver: u8,
    /// SHA-256 of the held stock ZIP this row was read out of. `[C]`
    pub source_zip_sha256: &'static str,
    /// Repo-relative directory of the extracted tree backing this row.
    pub held_evidence_path: &'static str,

    // ── Descriptive, non-energizing ──
    /// ASICs per hashboard. Family-level, `[D]` from Canaan's own `Avalon_mm`
    /// source (BUSL-1.1 — read as FACTS, never copied as code; see
    /// ). Never measured by us.
    pub asics_per_hashboard: Evidence<u16>,
    /// Hashboards per chassis, `[L]` from the `X3` token in `mm_hw_tag`.
    pub hashboards_per_chassis: Evidence<u8>,

    // ── Energizing. Unknown on every row — see the module header. ──
    pub freq_envelope_mhz: Evidence<FreqEnvelopeMhz>,
    pub core_voltage_envelope_mv: Evidence<CoreVoltageEnvelopeMv>,
    /// Empty on every row. A preset is a proven operating point, and we have none.
    pub tuning_presets: &'static [TuningPreset],
}

/// The parameters a caller would need before it could drive a chain. Producing
/// one requires bench-confirmed evidence for every field; no row in this
/// registry can produce one today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainParameters {
    pub freq: FreqEnvelopeMhz,
    pub core_voltage: CoreVoltageEnvelopeMv,
    pub preset: TuningPreset,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BoardRegistryError {
    #[error(
        "unknown Avalon model `{0}` — the registry is fail-closed on unknown models. Add a row \
         backed by bytes we hold; never a plausible default."
    )]
    UnknownModel(String),

    #[error(
        "board `{model_id}` has no bench-confirmed {parameter} {tag}: {why} — refusing to derive \
         chain parameters. This registry describes hardware; it does not authorize energizing it."
    )]
    NotEnergizable {
        model_id: &'static str,
        parameter: &'static str,
        tag: &'static str,
        why: &'static str,
    },
}

impl AvalonBoardProfile {
    /// Fail-closed resolution of everything needed to drive a chain.
    ///
    /// Returns `Err` for every row in the registry today, naming the first
    /// missing parameter, in a deterministic order (frequency → core voltage →
    /// tuning preset) so the surfaced reason is stable.
    pub fn chain_parameters(&self) -> Result<ChainParameters, BoardRegistryError> {
        let freq = *self.freq_envelope_mhz.confirmed().ok_or_else(|| {
            BoardRegistryError::NotEnergizable {
                model_id: self.model_id,
                parameter: "frequency envelope",
                tag: self.freq_envelope_mhz.tag(),
                why: self
                    .freq_envelope_mhz
                    .why_unknown()
                    .unwrap_or("value is inferred, not measured"),
            }
        })?;
        let core_voltage = *self.core_voltage_envelope_mv.confirmed().ok_or_else(|| {
            BoardRegistryError::NotEnergizable {
                model_id: self.model_id,
                parameter: "core-voltage envelope",
                tag: self.core_voltage_envelope_mv.tag(),
                why: self
                    .core_voltage_envelope_mv
                    .why_unknown()
                    .unwrap_or("value is inferred, not measured"),
            }
        })?;
        let preset = *self
            .tuning_presets
            .first()
            .ok_or(BoardRegistryError::NotEnergizable {
                model_id: self.model_id,
                parameter: "tuning preset",
                tag: "[?]",
                why: "no operating point has ever been captured and proven for this SKU",
            })?;
        Ok(ChainParameters {
            freq,
            core_voltage,
            preset,
        })
    }

    /// Whether this row could drive hardware. False for every row — and the
    /// only way to make it true is to land measured evidence, not to edit here.
    pub fn is_energizable(&self) -> bool {
        self.chain_parameters().is_ok()
    }
}

// ── Shared per-family evidence ───────────────────────────────────────────────

const AVALON_MM_ASIC_COUNT_SOURCE: &str =
    " \
     §4.3 [D] — read out of Canaan's Avalon_mm source (BUSL-1.1: facts only, no code copied)";

const X3_TAG_SOURCE: &str = " §4.2 [L] — \
     the `X3` token in the AUP hw_list tag decodes as a three-hashboard rack chassis";

/// The single reason every energizing field on every row is `Unknown`.
const ENCRYPTED_PAYLOAD: &str = "the AUP payload is an AES-CBC-encrypted K210 boot image \
     (aes_enable=0x01) whose master key is fused into the K210 OTP eFuse and is not present in any \
     archive we hold — no plaintext frequency/voltage/tuning table has ever been recovered \
     (AVALON_INDUSTRIAL_FW_RE.md §1, §3)";

const fn asics_per_hashboard(silicon: AvalonSilicon) -> Evidence<u16> {
    match silicon {
        AvalonSilicon::A3200CPlus => Evidence::Derived {
            value: 80,
            source: AVALON_MM_ASIC_COUNT_SOURCE,
        },
        AvalonSilicon::A3198S => Evidence::Derived {
            value: 78,
            source: AVALON_MM_ASIC_COUNT_SOURCE,
        },
        AvalonSilicon::A3197S => Evidence::Derived {
            value: 75,
            source: AVALON_MM_ASIC_COUNT_SOURCE,
        },
    }
}

const X3_CHASSIS: Evidence<u8> = Evidence::Likely {
    value: 3,
    source: X3_TAG_SOURCE,
};

const NO_FREQ: Evidence<FreqEnvelopeMhz> = Evidence::Unknown {
    why: ENCRYPTED_PAYLOAD,
};
const NO_VOLTAGE: Evidence<CoreVoltageEnvelopeMv> = Evidence::Unknown {
    why: ENCRYPTED_PAYLOAD,
};
const NO_PRESETS: &[TuningPreset] = &[];

// ── The registry ─────────────────────────────────────────────────────────────

/// All Canaan Avalon industrial SKUs we hold firmware bytes for.
///
/// **8 SKUs across 3 silicon families**, one row per held stock AUP:
///   * `A3200C-Plus` — a1346, a1346n
///   * `A3198S`      — a1466hs, a14x, a14xi
///   * `A3197S`      — a1566hs, a15x, a15xi
///
/// Ordered by silicon family, then by model id, so the table reads as a
/// generation ladder.
pub const REGISTRY: [AvalonBoardProfile; 8] = [
    // ── A3200C-Plus ──
    AvalonBoardProfile {
        model_id: "a1346",
        product_token: "A1346",
        silicon: AvalonSilicon::A3200CPlus,
        controller_soc: ControllerSoc::K210,
        mm_hw_tag: "MM4v1_X3",
        mm_sw_tags: &["MM317", "MM317_OOW"],
        cooling: CoolingClass::AirCooled,
        thermal_token: "Temp75",
        firmware_ver: "24041001_08b0955_0196aba",
        aup_fmt_ver: 2,
        source_zip_sha256: "ea4a836f975ea4ed5b1220d89644bc39c4fc704a2f76047c4068e8bfec28b3e6",
        held_evidence_path: "",
        asics_per_hashboard: asics_per_hashboard(AvalonSilicon::A3200CPlus),
        hashboards_per_chassis: X3_CHASSIS,
        freq_envelope_mhz: NO_FREQ,
        core_voltage_envelope_mv: NO_VOLTAGE,
        tuning_presets: NO_PRESETS,
    },
    AvalonBoardProfile {
        model_id: "a1346n",
        product_token: "A1346N",
        silicon: AvalonSilicon::A3200CPlus,
        controller_soc: ControllerSoc::K210,
        // Older gen-3 controller PCB — the only MM3-generation row in the set.
        mm_hw_tag: "MM3v2_X3",
        mm_sw_tags: &["MM317", "MM317_OOW"],
        cooling: CoolingClass::AirCooled,
        thermal_token: "Temp75",
        firmware_ver: "23052402_6d4cd98_52772d0",
        aup_fmt_ver: 2,
        source_zip_sha256: "684dc6767f2eff38e2cb2f13d9899b5a0e3376876f0b90d6513e8566387d1e8f",
        held_evidence_path: "",
        asics_per_hashboard: asics_per_hashboard(AvalonSilicon::A3200CPlus),
        hashboards_per_chassis: X3_CHASSIS,
        freq_envelope_mhz: NO_FREQ,
        core_voltage_envelope_mv: NO_VOLTAGE,
        tuning_presets: NO_PRESETS,
    },
    // ── A3198S ──
    AvalonBoardProfile {
        model_id: "a1466hs",
        // Canaan ships ONE image named for two products.
        product_token: "A1466HS_A14x",
        silicon: AvalonSilicon::A3198S,
        controller_soc: ControllerSoc::K210,
        // Same controller PCB as a14xi — see CoolingClass::LiquidOrHyperPowerUnresolved.
        mm_hw_tag: "MM4v1_X3_LC",
        mm_sw_tags: &["MM318_X2", "MM318_X2_OOW"],
        cooling: CoolingClass::LiquidOrHyperPowerUnresolved,
        // `MPO5000` appears ONLY in the archive name, never inside the AUP
        // header (AVALON_INDUSTRIAL_FW_RE.md §5.4) — recorded raw, not decoded.
        thermal_token: "Temp70_MPO5000",
        firmware_ver: "24102511_08b0955_aeae7e2t",
        aup_fmt_ver: 2,
        source_zip_sha256: "ef1d0f9ef82ee8030b62afd42053adf44cdfc4db4f70e1a276f94de956e16f52",
        held_evidence_path: "",
        asics_per_hashboard: asics_per_hashboard(AvalonSilicon::A3198S),
        hashboards_per_chassis: X3_CHASSIS,
        // The +448-byte delta vs a14xi is BELIEVED to be exactly the extended
        // hyper-power freq/voltage table (§5.4 [L]) — which is the one table we
        // would most want and the one we categorically cannot read.
        freq_envelope_mhz: NO_FREQ,
        core_voltage_envelope_mv: NO_VOLTAGE,
        tuning_presets: NO_PRESETS,
    },
    AvalonBoardProfile {
        model_id: "a14x",
        product_token: "A14x",
        silicon: AvalonSilicon::A3198S,
        controller_soc: ControllerSoc::K210,
        mm_hw_tag: "MM4v1_X3",
        mm_sw_tags: &["MM318_X2", "MM318_X2_OOW"],
        cooling: CoolingClass::AirCooled,
        thermal_token: "Temp70",
        firmware_ver: "24061401_08b0955_841e057",
        aup_fmt_ver: 2,
        source_zip_sha256: "e69606341ea56a9927b8c929dac13756264de1d75a866c4251997bc96520076d",
        held_evidence_path: "",
        asics_per_hashboard: asics_per_hashboard(AvalonSilicon::A3198S),
        hashboards_per_chassis: X3_CHASSIS,
        freq_envelope_mhz: NO_FREQ,
        core_voltage_envelope_mv: NO_VOLTAGE,
        tuning_presets: NO_PRESETS,
    },
    AvalonBoardProfile {
        model_id: "a14xi",
        product_token: "A14xI",
        silicon: AvalonSilicon::A3198S,
        controller_soc: ControllerSoc::K210,
        mm_hw_tag: "MM4v1_X3_LC",
        mm_sw_tags: &["MM318_X2", "MM318_X2_OOW"],
        cooling: CoolingClass::LiquidOrHyperPowerUnresolved,
        thermal_token: "LC",
        firmware_ver: "24043002_08b0955_e9f87ac",
        aup_fmt_ver: 2,
        source_zip_sha256: "a2b49f19a93d294251dc9fa5299d315cdb6631b6d5f74d93896411c5ddaa9ec5",
        held_evidence_path: "",
        asics_per_hashboard: asics_per_hashboard(AvalonSilicon::A3198S),
        hashboards_per_chassis: X3_CHASSIS,
        freq_envelope_mhz: NO_FREQ,
        core_voltage_envelope_mv: NO_VOLTAGE,
        tuning_presets: NO_PRESETS,
    },
    // ── A3197S ──
    AvalonBoardProfile {
        model_id: "a1566hs",
        product_token: "A1566HS_A15xI",
        silicon: AvalonSilicon::A3197S,
        controller_soc: ControllerSoc::K210,
        mm_hw_tag: "MM4v2_X3_LC",
        mm_sw_tags: &["MM319", "MM319_OOW"],
        cooling: CoolingClass::LiquidOrHyperPowerUnresolved,
        thermal_token: "LC",
        firmware_ver: "24071901_25462b2_629a6f2t",
        aup_fmt_ver: 2,
        source_zip_sha256: "9e2b56c43ee05d0f91675b473ebcebcc92b60a883ec6a77f73c7346c19974317",
        held_evidence_path: "",
        asics_per_hashboard: asics_per_hashboard(AvalonSilicon::A3197S),
        hashboards_per_chassis: X3_CHASSIS,
        freq_envelope_mhz: NO_FREQ,
        core_voltage_envelope_mv: NO_VOLTAGE,
        tuning_presets: NO_PRESETS,
    },
    AvalonBoardProfile {
        model_id: "a15x",
        product_token: "A15x",
        silicon: AvalonSilicon::A3197S,
        controller_soc: ControllerSoc::K210,
        mm_hw_tag: "MM4v2_X3",
        mm_sw_tags: &["MM319", "MM319_OOW"],
        cooling: CoolingClass::AirCooled,
        thermal_token: "Temp70",
        firmware_ver: "24082801_25462b2_3a3e74f",
        aup_fmt_ver: 2,
        source_zip_sha256: "74f293c9ade16559f79f431a4d367208379fc5a5186c9b0897ec2cdc942a294d",
        held_evidence_path: "",
        asics_per_hashboard: asics_per_hashboard(AvalonSilicon::A3197S),
        hashboards_per_chassis: X3_CHASSIS,
        freq_envelope_mhz: NO_FREQ,
        core_voltage_envelope_mv: NO_VOLTAGE,
        tuning_presets: NO_PRESETS,
    },
    AvalonBoardProfile {
        model_id: "a15xi",
        product_token: "A15xI",
        silicon: AvalonSilicon::A3197S,
        controller_soc: ControllerSoc::K210,
        mm_hw_tag: "MM4v2_X3_LC",
        mm_sw_tags: &["MM319", "MM319_OOW"],
        cooling: CoolingClass::LiquidOrHyperPowerUnresolved,
        thermal_token: "LC",
        firmware_ver: "24090201_25462b2_03d0d8f",
        aup_fmt_ver: 2,
        source_zip_sha256: "9fa5ad9ce40ca1284462beaeb83ba1459291a47c96d0a8fb018a8f30695ca6b9",
        held_evidence_path: "",
        asics_per_hashboard: asics_per_hashboard(AvalonSilicon::A3197S),
        hashboards_per_chassis: X3_CHASSIS,
        freq_envelope_mhz: NO_FREQ,
        core_voltage_envelope_mv: NO_VOLTAGE,
        tuning_presets: NO_PRESETS,
    },
];

/// Resolve a board by `model_id` or by `product_token`, case-insensitively.
///
/// FAIL-CLOSED: anything not in [`REGISTRY`] is an error, never a fallback row.
/// SKUs we do not hold firmware for (Avalon Q, A16xx, the K230 home line) are
/// deliberately absent and therefore deliberately unresolvable.
pub fn resolve(model: &str) -> Result<&'static AvalonBoardProfile, BoardRegistryError> {
    let needle = model.trim();
    REGISTRY
        .iter()
        .find(|b| {
            b.model_id.eq_ignore_ascii_case(needle) || b.product_token.eq_ignore_ascii_case(needle)
        })
        .ok_or_else(|| BoardRegistryError::UnknownModel(model.to_string()))
}

/// Every registry row belonging to one silicon family.
pub fn by_silicon(silicon: AvalonSilicon) -> impl Iterator<Item = &'static AvalonBoardProfile> {
    REGISTRY.iter().filter(move |b| b.silicon == silicon)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Shape ──

    #[test]
    fn registry_declares_eight_skus_across_three_silicon_families() {
        assert_eq!(REGISTRY.len(), 8, "one row per held stock AUP");
        assert_eq!(AvalonSilicon::ALL.len(), 3);
        for family in AvalonSilicon::ALL {
            assert!(
                by_silicon(family).next().is_some(),
                "{family} has no rows — a declared family must be represented"
            );
        }
        assert_eq!(by_silicon(AvalonSilicon::A3200CPlus).count(), 2);
        assert_eq!(by_silicon(AvalonSilicon::A3198S).count(), 3);
        assert_eq!(by_silicon(AvalonSilicon::A3197S).count(), 3);
    }

    #[test]
    fn model_ids_and_product_tokens_are_unique() {
        for (i, a) in REGISTRY.iter().enumerate() {
            for b in REGISTRY.iter().skip(i + 1) {
                assert_ne!(a.model_id, b.model_id);
                assert_ne!(a.product_token, b.product_token);
                assert_ne!(
                    a.source_zip_sha256, b.source_zip_sha256,
                    "two rows cannot be backed by the same firmware image"
                );
                assert_ne!(a.firmware_ver, b.firmware_ver);
            }
        }
    }

    // ── The load-bearing invariant ──

    /// LOAD-BEARING. Declaring a board must never make it energizable. If this
    /// test ever needs changing, that change is an operator decision backed by a
    /// bench capture — not a refactor.
    #[test]
    fn no_registry_row_is_energizable() {
        for b in REGISTRY.iter() {
            assert!(
                !b.is_energizable(),
                "{} became energizable — the registry must describe hardware, never authorize it",
                b.model_id
            );
        }
    }

    #[test]
    fn chain_parameters_fails_closed_on_every_row_naming_the_missing_parameter() {
        for b in REGISTRY.iter() {
            let err = b
                .chain_parameters()
                .expect_err("must fail closed on unverified chip-facing values");
            match err {
                BoardRegistryError::NotEnergizable {
                    model_id,
                    parameter,
                    tag,
                    why,
                } => {
                    assert_eq!(model_id, b.model_id);
                    // Deterministic resolution order: frequency surfaces first.
                    assert_eq!(parameter, "frequency envelope");
                    assert_eq!(tag, "[?]");
                    assert!(
                        why.contains("AES-CBC") && why.contains("OTP eFuse"),
                        "the reason must name the real blocker, not a placeholder"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn no_row_carries_a_frequency_voltage_or_tuning_value_at_any_confidence() {
        for b in REGISTRY.iter() {
            assert!(
                b.freq_envelope_mhz.is_unknown(),
                "{}: a frequency appeared in the registry",
                b.model_id
            );
            assert!(
                b.core_voltage_envelope_mv.is_unknown(),
                "{}: a core voltage appeared in the registry",
                b.model_id
            );
            assert!(
                b.tuning_presets.is_empty(),
                "{}: a tuning preset appeared in the registry",
                b.model_id
            );
            // Not even a display-only inference.
            assert!(b.freq_envelope_mhz.any().is_none());
            assert!(b.core_voltage_envelope_mv.any().is_none());
        }
    }

    #[test]
    fn a_confirmed_envelope_would_still_need_a_proven_preset() {
        // Mutation guard: proves the gate is a conjunction, not just the first
        // check. A row with both envelopes measured but no proven operating
        // point still refuses.
        let mut row = REGISTRY[0];
        row.freq_envelope_mhz = Evidence::Confirmed {
            value: FreqEnvelopeMhz {
                min: 1,
                max: 2,
                default: 1,
            },
            source: "TEST-ONLY synthetic value, never a real capture",
        };
        row.core_voltage_envelope_mv = Evidence::Confirmed {
            value: CoreVoltageEnvelopeMv {
                min: 1,
                max: 2,
                default: 1,
            },
            source: "TEST-ONLY synthetic value, never a real capture",
        };
        assert!(!row.is_energizable());
        match row.chain_parameters().expect_err("still fails closed") {
            BoardRegistryError::NotEnergizable { parameter, .. } => {
                assert_eq!(parameter, "tuning preset")
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // ── Provenance ──

    #[test]
    fn derived_and_likely_values_are_never_readable_as_confirmed() {
        for b in REGISTRY.iter() {
            assert_eq!(b.asics_per_hashboard.tag(), "[D]");
            assert!(
                b.asics_per_hashboard.confirmed().is_none(),
                "a derived chip count must never read as measured"
            );
            assert!(b.asics_per_hashboard.any().is_some());

            assert_eq!(b.hashboards_per_chassis.tag(), "[L]");
            assert!(b.hashboards_per_chassis.confirmed().is_none());
            assert_eq!(b.hashboards_per_chassis.any(), Some(&3));
        }
    }

    #[test]
    fn chip_counts_are_a_property_of_the_silicon_not_the_sku() {
        for family in AvalonSilicon::ALL {
            let counts: Vec<_> = by_silicon(family)
                .map(|b| *b.asics_per_hashboard.any().unwrap())
                .collect();
            assert!(
                counts.windows(2).all(|w| w[0] == w[1]),
                "{family}: rows disagree on chips/board"
            );
        }
        assert_eq!(
            *by_silicon(AvalonSilicon::A3200CPlus)
                .next()
                .unwrap()
                .asics_per_hashboard
                .any()
                .unwrap(),
            80
        );
        assert_eq!(
            *by_silicon(AvalonSilicon::A3198S)
                .next()
                .unwrap()
                .asics_per_hashboard
                .any()
                .unwrap(),
            78
        );
        assert_eq!(
            *by_silicon(AvalonSilicon::A3197S)
                .next()
                .unwrap()
                .asics_per_hashboard
                .any()
                .unwrap(),
            75
        );
    }

    #[test]
    fn every_row_cites_held_bytes() {
        for b in REGISTRY.iter() {
            assert!(
                b.held_evidence_path
                    .starts_with(""),
                "{}: evidence path must point at bytes we hold",
                b.model_id
            );
            assert!(
                b.held_evidence_path.contains(b.model_id),
                "{}: evidence path must match the model id",
                b.model_id
            );
            assert_eq!(
                b.source_zip_sha256.len(),
                64,
                "{}: source hash must be a full SHA-256",
                b.model_id
            );
            assert!(b.source_zip_sha256.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(b.aup_fmt_ver, 2, "every held industrial AUP is fmt_ver 2");
            assert_eq!(b.controller_soc, ControllerSoc::K210);
            assert!(!b.mm_sw_tags.is_empty());
            assert!(!b.mm_hw_tag.is_empty());
        }
    }

    /// `every_row_cites_held_bytes` proves the path has the right *shape*; it
    /// does not prove the bytes are actually there. A row could cite
    /// `.../a99x/` with a plausible 64-hex hash and pass — the phantom-reference
    /// class of bug (cf. the phantom CV1835 defconfig, hardware-enablement rank
    /// 11). This closes it: every `held_evidence_path` must resolve to a real
    /// directory that actually contains a `.aup` and a `_summary.json`.
    ///
    /// The crate manifest lives at `<repo>/shared/dcent-avalon-proto`, so the
    /// repo root is two levels up. If the corpus is ever relocated, this fails
    /// loudly with the offending model id instead of letting the registry drift
    /// into citing bytes that no longer exist.
    #[test]
    fn every_held_evidence_path_exists_and_contains_an_aup() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("manifest dir has a repo root two levels up");

        for b in REGISTRY.iter() {
            let dir = repo_root.join(b.held_evidence_path);
            assert!(
                dir.is_dir(),
                "{}: held_evidence_path {} does not resolve to a directory at {}",
                b.model_id,
                b.held_evidence_path,
                dir.display()
            );

            // The directory must actually hold the vendor artifacts the row
            // claims to be sourced from — a `.aup` and its decoded summary,
            // somewhere in the (one-subdir-deep) tree.
            let mut has_aup = false;
            let mut has_summary = false;
            let mut stack = vec![dir.clone()];
            while let Some(d) = stack.pop() {
                let Ok(entries) = std::fs::read_dir(&d) else {
                    continue;
                };
                for e in entries.flatten() {
                    let path = e.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.ends_with(".aup") {
                            has_aup = true;
                        }
                        if name == "_summary.json" {
                            has_summary = true;
                        }
                    }
                }
            }
            assert!(
                has_aup,
                "{}: {} exists but holds no .aup",
                b.model_id, b.held_evidence_path
            );
            assert!(
                has_summary,
                "{}: {} exists but holds no _summary.json",
                b.model_id, b.held_evidence_path
            );
        }
    }

    #[test]
    fn cooling_ambiguity_is_preserved_wherever_the_hw_tag_says_lc() {
        for b in REGISTRY.iter() {
            let lc_tag = b.mm_hw_tag.ends_with("_LC");
            match b.cooling {
                CoolingClass::LiquidOrHyperPowerUnresolved => assert!(
                    lc_tag,
                    "{}: unresolved cooling without an _LC hw tag",
                    b.model_id
                ),
                CoolingClass::AirCooled => assert!(
                    !lc_tag,
                    "{}: an _LC hw tag was collapsed to air-cooled",
                    b.model_id
                ),
            }
        }
        // The specific fact that forces the ambiguity: one controller PCB tag
        // shared by an immersion SKU and a hyper-power SKU.
        let shared: Vec<_> = REGISTRY
            .iter()
            .filter(|b| b.mm_hw_tag == "MM4v1_X3_LC")
            .map(|b| b.model_id)
            .collect();
        assert_eq!(shared, vec!["a1466hs", "a14xi"]);
    }

    #[test]
    fn software_tag_families_track_the_silicon() {
        for b in REGISTRY.iter() {
            let expected = match b.silicon {
                AvalonSilicon::A3200CPlus => "MM317",
                AvalonSilicon::A3198S => "MM318",
                AvalonSilicon::A3197S => "MM319",
            };
            assert!(
                b.mm_sw_tags.iter().all(|t| t.starts_with(expected)),
                "{}: sw_list {:?} does not match {} family",
                b.model_id,
                b.mm_sw_tags,
                b.silicon
            );
        }
    }

    // ── Resolution ──

    #[test]
    fn resolve_finds_every_row_by_id_and_by_product_token() {
        for b in REGISTRY.iter() {
            assert_eq!(resolve(b.model_id).unwrap().model_id, b.model_id);
            assert_eq!(resolve(b.product_token).unwrap().model_id, b.model_id);
            assert_eq!(
                resolve(&b.model_id.to_uppercase()).unwrap().model_id,
                b.model_id
            );
            assert_eq!(
                resolve(&format!("  {}  ", b.model_id)).unwrap().model_id,
                b.model_id
            );
        }
    }

    #[test]
    fn resolve_is_fail_closed_on_everything_else() {
        // Real Avalon products we hold NO firmware for must not resolve to a
        // near neighbour.
        for unknown in [
            "", "avalon-q", "a16xx", "a1666", "nano3s", "nano 3", "mini3", "a1246", "a1146", "a15",
            "a15xx", "A3197S",
        ] {
            match resolve(unknown) {
                Err(BoardRegistryError::UnknownModel(m)) => assert_eq!(m, unknown),
                other => panic!("`{unknown}` must not resolve, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_error_messages_say_what_to_do() {
        let unknown = resolve("avalon-q").unwrap_err().to_string();
        assert!(unknown.contains("fail-closed"));
        assert!(unknown.contains("never a plausible default"));

        let gated = REGISTRY[0].chain_parameters().unwrap_err().to_string();
        assert!(gated.contains("does not authorize energizing"));
        assert!(gated.contains("a1346"));
    }
}
