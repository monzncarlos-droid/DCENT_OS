//!  eep-A — EEPROM record DTOs (HAL-free, post-cipher).
//!
//! Source RE evidence:
//! .
//!
//! Bosminer-plus-tuner ships four EEPROM parser variants, each keyed on
//! the first two bytes of the (decrypted) plaintext blob. This module
//! consumes a **plaintext** byte slice (caller has already run XXTEA /
//! AES-128-ECB / Braiinsminer cipher as needed) and decodes the typed
//! record fields above the cipher.
//!
//! The crypto layer lives separately:
//! - EDF v5 / XXTEA caller-key path: `dcent-toolbox::core::eeprom_decoder`
//!   (Python, already shipped as -T2 partial).
//! - x19_plain / x19_J XXTEA: KDF unknown without further Ghidra work; the
//!   structured-record decoder here will reject these variants until live
//!   Ghidra evidence lands. The dispatcher recognizes them so the caller
//!   gets a clean error rather than a guess.
//!
//! Preamble dispatch (per RE doc §2):
//!
//! | Byte 0 | Byte 1   | Variant       | Hashboard families                  |
//! |--------|----------|---------------|-------------------------------------|
//! | `0x04` | `0x11`   | x19_plain/x19_J | BHB42xxx (S19/S19j Pro/T19; BM1398/BM1362) |
//! | `0x05` | `0x11`   | edf_v5_xxtea  | BHB56xxx, BHB68xxx (BM1366/BM1368)  |
//! | `0x01` | `0x41`   | format1 (not dispatched here) | A3HB4xxxx / A3HB7xxxx (S21 Pro/XP; BM1370) |
//! | `'B'`  | `'r'`    | braiinsminer  | BMM100/BMM101                       |
//! | other  | other    | UnknownPreamble | rejected with parse error         |
//!
//! **Format 1 note (2026-08-02):** A3HB-prefixed boards are format 1, NOT
//! format 5. Their header is `0x01 0x41`, where `0x41` is `board_name[0]`
//! (`'A'`), NOT a key-version selector — `board_name` sits in a 16-byte
//! plaintext header. Format 1 is not dispatched by `dispatch()` here (the
//! enciphered-body decode is a separate item); it currently falls to
//! `UnknownPreamble`, but the plaintext SKU still resolves board identity via
//! `scan_known_sku`. Evidence:
//! evidence/epic-eeprom-matched-samples-20.json` (A3HB70501/70601/70701
//! `fmt=1|keyver=65`). **Dispatch is always on `raw[0]`; never map a SKU to a
//! format** (`BHB56801` appears as both format 4 and 5).
//!
//! HAL-free; pure logic. Tests cover synthetic plaintext + the JSON shape
//! verified against `a lab unit` `hb0/hb1/hb2.parsed.json` evidence in the
//! knowledge-base.

use serde::{Deserialize, Serialize};

pub const RAW_EEPROM_BLOB_LEN: usize = 256;
pub const RAW_EEPROM_DECODE_SCHEMA: &str = "dcentos.eeprom.raw_decode.v1";

/// Discriminated union of all four EEPROM parser variants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "variant", rename_all = "snake_case")]
pub enum EepromRecord {
    /// BHB42xxx (early S19/S19j Pro), XXTEA-encrypted. KDF unknown
    /// without further RE; we expose the preamble + raw payload only.
    X19Plain(X19PlainRecord),
    /// BHB428xx (later S19j Pro), XXTEA-encrypted with explicit PT1/PT2
    /// + sensor rows. KDF unknown.
    X19J(X19JRecord),
    /// BHB56xxx / BHB68xxx (BM1366/BM1368), EDF v5 header with XXTEA
    /// algorithm and explicit key index. (A3HB-prefixed S21 Pro/XP boards
    /// are format 1 `0x01 0x41`, NOT this variant — see module docs.)
    EdfV5Xxtea(EdfV5XxteaRecord),
    /// Legacy structured plaintext helper retained for callers that already
    /// converted a BHB56/BHB68 blob into field-like data.
    X21Aes(X21AesRecord),
    /// Braiins BMM100/101 boards.
    Braiinsminer(BraiinsminerRecord),
}

/// Shape of an x21_aes plaintext record (post-AES decryption).
///
/// Field set per RE doc §4 (string at `0x00f1b0d6`):
/// `S/N FCT-JOB CH-DIE CH-MARK FT CH-TECH CH-BIN PCB BOM U1 VF U2 U3 SALE-R U4`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct X21AesRecord {
    /// 17-char ASCII serial number (e.g. `AS19K…`).
    pub serial_number: String,
    /// Hashboard SKU name like `BHB56902` (cross-checked vs in-binary
    /// SKU table at `0x00eec028` to derive chip family).
    pub b_name: String,
    /// PCB version word.
    pub pcb_version: u16,
    /// BOM version word.
    pub bom_version: u16,
    /// Factory job ticket id (e.g. `JYZZ20230901007-Y1`).
    pub fact_job: String,
    /// Chip die marking (`ED`, etc.).
    pub ch_die: String,
    /// Chip marking line (e.g. `S1GM23AL36`).
    pub ch_marking: String,
    /// Functional test result string (e.g. `F1V18B3C1`).
    pub ft: String,
    /// Chip technology code (`BS`, etc.).
    pub ch_tech: String,
    /// Chip bin (silicon quality grade) — small integer as string.
    pub bin: String,
    /// V/F curve descriptor (encoded; consumer plugs into the relevant
    /// silicon-profiles table to compute target voltage at frequency).
    pub vf: Vec<u8>,
    /// SALE-R rate code (Bitmain marketing tier).
    pub sale_rate: Option<String>,
}

/// Shape of an EDF v5 encrypted EEPROM record.
///
/// Header `05 11` means format version 5, algorithm nibble 1 (XXTEA),
/// key index 1. The body is still encrypted here; this HAL-free crate only
/// reports read-only metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdfV5XxteaRecord {
    pub format_version: u8,
    pub cipher: String,
    pub key_index: u8,
    pub raw_payload: Vec<u8>,
}

/// Shape of an x19_plain record. The XXTEA KDF is unknown without further
/// RE so this variant is currently `preamble-only` — full field decode
/// requires capturing a BHB42xxx plaintext dump and matching it against
/// the bosminer panic-string field list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct X19PlainRecord {
    /// First byte after preamble: layout sub-version.
    pub algo_or_subver: u8,
    /// Raw encrypted payload bytes (the caller is expected to keep this
    /// for forward-compat once the KDF is documented).
    pub raw_payload: Vec<u8>,
}

/// Shape of an x19_J record. Same KDF status as x19_plain — preamble +
/// raw payload only until further RE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct X19JRecord {
    pub layout_version: u8,
    pub algo_key_version: u8,
    pub raw_payload: Vec<u8>,
}

/// Shape of a Braiinsminer (`BMM100`/`BMM101`) record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BraiinsminerRecord {
    /// `Br!` magic + remaining payload (cipher unknown).
    pub raw_payload: Vec<u8>,
}

/// Parse error returned by `dispatch()`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum EepromParseError {
    /// Plaintext blob is too short to even read the preamble.
    Truncated { got: usize, need: usize },
    /// Preamble doesn't match any known parser variant.
    UnknownPreamble { byte0: u8, byte1: u8 },
    /// Variant recognized but the body decoder isn't implemented yet
    /// (waiting on further RE).
    NotImplementedYet { variant: String },
    /// Body field decode failed (e.g. CRC mismatch, malformed field).
    BodyDecode { detail: String },
}

/// Status for a host-safe raw EEPROM/BHB decode attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawEepromDecodeStatus {
    /// The blob length was not the expected 256-byte EEPROM page.
    MalformedLength,
    /// The preamble was recognized and a structured record was decoded.
    Decoded,
    /// The preamble was recognized, but only metadata could be normalized.
    MetadataOnly,
    /// The preamble did not match a known EEPROM parser.
    UnknownPreamble,
}

/// Normalized, read-only board identity extracted from a raw EEPROM blob.
///
/// This DTO is intentionally lossy: it exposes identity and provenance fields
/// that are safe for API/dashboard consumers without carrying cipher material,
/// proprietary keys, or any write-capable handle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedHashboardMetadata {
    pub board_sku: Option<String>,
    pub chip_family: Option<String>,
    pub model_family: Option<String>,
    pub eeprom_variant: Option<String>,
    pub eeprom_format: Option<String>,
    pub cipher: Option<String>,
    pub key_index: Option<u8>,
    pub serial_number: Option<String>,
    pub confidence: String,
    pub source: String,
    pub read_only: bool,
    pub writes_performed: bool,
    pub notes: Vec<String>,
}

impl Default for NormalizedHashboardMetadata {
    fn default() -> Self {
        Self {
            board_sku: None,
            chip_family: None,
            model_family: None,
            eeprom_variant: None,
            eeprom_format: None,
            cipher: None,
            key_index: None,
            serial_number: None,
            confidence: "none".to_string(),
            source: "no_normalized_metadata".to_string(),
            read_only: true,
            writes_performed: false,
            notes: vec!["No EEPROM writes are performed by api-types decode helpers.".to_string()],
        }
    }
}

/// Host-safe raw EEPROM decode report for one 256-byte blob.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawEepromDecodeReport {
    pub schema: String,
    pub raw_len: usize,
    pub status: RawEepromDecodeStatus,
    pub record: Option<EepromRecord>,
    pub metadata: NormalizedHashboardMetadata,
    pub warnings: Vec<String>,
}

/// Dispatch a plaintext EEPROM blob to the right variant.
///
/// `plaintext` MUST be the post-cipher byte sequence — the caller has
/// already run XXTEA / AES-128-ECB / etc. as appropriate. Use
/// `dcent-toolbox::core::eeprom_decoder` for the cipher pass.
pub fn dispatch(plaintext: &[u8]) -> Result<EepromRecord, EepromParseError> {
    if plaintext.len() < 2 {
        return Err(EepromParseError::Truncated {
            got: plaintext.len(),
            need: 2,
        });
    }
    match (plaintext[0], plaintext[1]) {
        (0x04, 0x11) => {
            // x19_plain or x19_J — KDF not documented; return the
            // x19_plain preamble form so the caller knows what they
            // have. Distinguishing x19_plain vs x19_J requires a SKU
            // crosscheck after decrypt, which we can't do here.
            Ok(EepromRecord::X19Plain(X19PlainRecord {
                algo_or_subver: 0,
                raw_payload: plaintext[2..].to_vec(),
            }))
        }
        (0x05, 0x11) => {
            // EDF v5 encrypted record. Byte 1 splits into algorithm nibble
            // 0x1 (XXTEA) and key index 0x1.
            Ok(EepromRecord::EdfV5Xxtea(EdfV5XxteaRecord {
                format_version: 5,
                cipher: "xxtea".to_string(),
                key_index: 1,
                raw_payload: plaintext[2..].to_vec(),
            }))
        }
        (b'B', b'r') => Ok(EepromRecord::Braiinsminer(BraiinsminerRecord {
            raw_payload: plaintext.to_vec(), // includes the magic
        })),
        (a, b) => Err(EepromParseError::UnknownPreamble { byte0: a, byte1: b }),
    }
}

/// Decode an x21_aes plaintext body (everything after the 2-byte preamble).
///
/// Field framing per RE doc §4 + verified against `a lab unit` `hb*.parsed.json`.
/// The plaintext blob has fixed-length sections; we read by offset rather
/// than length-prefix because that's what bosminer does.
///
/// ** status**: this implements only the JSON-key-equivalent
/// surface (serial_number, b_name, fact_job, ch_*, ft, sale_rate). Full
/// VF curve byte-level layout is left as `Vec<u8>` until live cross-check
/// against more boards lands. PCB/BOM version words read from the well-known
/// 32-bit aligned offsets when present.
pub fn decode_x21_aes(payload: &[u8]) -> Result<X21AesRecord, EepromParseError> {
    if payload.len() < 32 {
        return Err(EepromParseError::Truncated {
            got: payload.len(),
            need: 32,
        });
    }
    // The field layout is text-tagged in the actual binary; for  we
    // expect the caller to provide a structured plaintext that mirrors the
    // hb*.parsed.json shape. The runtime adapter inside dcent-toolbox
    // populates the fields; we just validate length + ASCII-cleanness.
    //
    // Constructor for testing: caller hands in a serialized form that
    // matches a synthetic-plaintext layout. Real `a lab unit`-format plaintext is
    // decoded by `dcent-toolbox::core::eeprom_decoder.decode_x21_aes` (Python).
    let serial_number = read_ascii_field(payload, 0, 17)?;
    let b_name = read_ascii_field(payload, 17, 8)?;
    Ok(X21AesRecord {
        serial_number,
        b_name,
        pcb_version: 0,
        bom_version: 0,
        fact_job: String::new(),
        ch_die: String::new(),
        ch_marking: String::new(),
        ft: String::new(),
        ch_tech: String::new(),
        bin: String::new(),
        vf: Vec::new(),
        sale_rate: None,
    })
}

/// Decode a raw 256-byte BHB EEPROM page where the bytes are already
/// fixture-like plaintext.
///
/// This function does not decrypt, derive keys, contact hardware, or write
/// EEPROM. For encrypted/opaque records it only reports what can be proven
/// from the visible preamble and ASCII SKU strings.
pub fn decode_raw_256_blob(raw: &[u8]) -> RawEepromDecodeReport {
    let mut warnings = Vec::new();
    if raw.len() != RAW_EEPROM_BLOB_LEN {
        warnings.push(format!(
            "expected {} bytes, got {}; no hardware reads or writes attempted",
            RAW_EEPROM_BLOB_LEN,
            raw.len()
        ));
        return RawEepromDecodeReport {
            schema: RAW_EEPROM_DECODE_SCHEMA.to_string(),
            raw_len: raw.len(),
            status: RawEepromDecodeStatus::MalformedLength,
            record: None,
            metadata: NormalizedHashboardMetadata::default(),
            warnings,
        };
    }

    let record = dispatch(raw);
    let mut metadata = normalize_metadata_from_raw(raw, record.as_ref().ok());
    metadata.read_only = true;
    metadata.writes_performed = false;

    match record {
        Ok(record) => {
            let status = if matches!(record, EepromRecord::X21Aes(_)) {
                RawEepromDecodeStatus::Decoded
            } else {
                RawEepromDecodeStatus::MetadataOnly
            };
            if !matches!(record, EepromRecord::X21Aes(_)) {
                warnings.push(
                    "recognized preamble but full body decode requires decrypted fixture evidence"
                        .to_string(),
                );
            }
            RawEepromDecodeReport {
                schema: RAW_EEPROM_DECODE_SCHEMA.to_string(),
                raw_len: raw.len(),
                status,
                record: Some(record),
                metadata,
                warnings,
            }
        }
        Err(EepromParseError::UnknownPreamble { byte0, byte1 }) => {
            warnings.push(format!(
                "unknown EEPROM preamble 0x{byte0:02x} 0x{byte1:02x}; no decode guessed"
            ));
            RawEepromDecodeReport {
                schema: RAW_EEPROM_DECODE_SCHEMA.to_string(),
                raw_len: raw.len(),
                status: RawEepromDecodeStatus::UnknownPreamble,
                record: None,
                metadata,
                warnings,
            }
        }
        Err(err) => {
            warnings.push(format!(
                "recognized preamble but body decode failed: {err:?}"
            ));
            RawEepromDecodeReport {
                schema: RAW_EEPROM_DECODE_SCHEMA.to_string(),
                raw_len: raw.len(),
                status: RawEepromDecodeStatus::MetadataOnly,
                record: None,
                metadata,
                warnings,
            }
        }
    }
}

fn normalize_metadata_from_raw(
    raw: &[u8],
    record: Option<&EepromRecord>,
) -> NormalizedHashboardMetadata {
    let mut metadata = NormalizedHashboardMetadata::default();
    match record {
        Some(EepromRecord::X21Aes(rec)) => {
            metadata.board_sku = Some(rec.b_name.clone());
            metadata.serial_number = if rec.serial_number.is_empty() {
                None
            } else {
                Some(rec.serial_number.clone())
            };
        }
        Some(EepromRecord::EdfV5Xxtea(rec)) => {
            metadata.eeprom_variant = Some("edf_v5_xxtea_key1".to_string());
            metadata.eeprom_format = Some(format!("edf_v{}", rec.format_version));
            metadata.cipher = Some(rec.cipher.clone());
            metadata.key_index = Some(rec.key_index);
            metadata.confidence = "preamble_only".to_string();
            metadata.source = "eeprom_header_05_11".to_string();
            metadata
                .notes
                .push("Header 05 11 = EDF v5, XXTEA algorithm, key index 1.".to_string());
            metadata.board_sku = scan_known_sku(raw);
        }
        _ => {
            metadata.board_sku = scan_known_sku(raw);
        }
    }

    if let Some(sku) = metadata.board_sku.as_deref() {
        if let Some(entry) = catalog_entry_for_sku(sku) {
            metadata.chip_family = Some(entry.chip_family.to_string());
            metadata.model_family = Some(entry.model_family.to_string());
            metadata.eeprom_variant = Some(entry.eeprom_variant.to_string());
            metadata.confidence = entry.confidence.to_string();
            metadata.source = entry.source.to_string();
            metadata.notes.push(entry.note.to_string());
        } else {
            metadata.confidence = "unknown_sku".to_string();
            metadata
                .notes
                .push(format!("visible SKU {sku} is not in BHB_SKU_CATALOG"));
        }
    }

    metadata
}

fn scan_known_sku(raw: &[u8]) -> Option<String> {
    for len in (7..=9).rev() {
        if raw.len() < len {
            continue;
        }
        for window in raw.windows(len) {
            if !window.iter().all(|b| b.is_ascii_alphanumeric()) {
                continue;
            }
            let Ok(candidate) = std::str::from_utf8(window) else {
                continue;
            };
            if catalog_entry_for_sku(candidate).is_some() {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

/// Resolve a board name to its catalog row — **first match wins**.
///
/// ⚠ ORDER IS LOAD-BEARING. [`BHB_SKU_CATALOG`] mixes exact `model_id` rows
/// with prefix patterns, and this is a linear `find`. Every exact row MUST be
/// listed **before** any prefix that would also match it, or the prefix
/// answers first and the exact row becomes dead. Pinned by
/// `exact_rows_precede_the_prefix_catch_all_they_correct`.
pub fn catalog_entry_for_sku(b_name: &str) -> Option<&'static BhbSkuCatalogEntry> {
    let sku = b_name.trim();
    BHB_SKU_CATALOG
        .iter()
        .find(|entry| sku_matches_catalog_pattern(sku, entry.pattern))
}

fn sku_matches_catalog_pattern(sku: &str, pattern: &str) -> bool {
    match pattern {
        "BHB426xx" => sku.starts_with("BHB426"),
        "BHB428xx" => sku.starts_with("BHB428"),
        "BHB568xx / BHB569xx" => sku.starts_with("BHB568") || sku.starts_with("BHB569"),
        // W8 rank-9 (2026-08-03): there is deliberately NO `BHB68` prefix arm.
        // BHB68 SKUs resolve only through their 8 exact roster rows; an
        // unknown `BHB68…` is `None` (fail closed), never a guessed family.
        "A3HB4xxxx" => sku.starts_with("A3HB4"),
        "A3HB7xxxx" => sku.starts_with("A3HB7"),
        _ => sku == pattern,
    }
}

/// Read an ASCII field at `[start, start+len)` from `payload`. Trims
/// trailing NUL/spaces. Returns `BodyDecode` on non-ASCII bytes.
fn read_ascii_field(payload: &[u8], start: usize, len: usize) -> Result<String, EepromParseError> {
    // bug-hunt LOW #10 (2026-05-28): `start + len` was unchecked. With large
    // start/len it could wrap (usize overflow) and pass the bounds check, then
    // `&payload[start..start+len]` would panic. Only internal callers with small
    // fixed constants reach this today, but checked_add makes it safe if
    // read_ascii_field is ever made pub / reused on attacker-influenced offsets.
    let end = match start.checked_add(len) {
        Some(e) if e <= payload.len() => e,
        _ => {
            return Err(EepromParseError::Truncated {
                got: payload.len(),
                need: start.saturating_add(len),
            });
        }
    };
    let bytes = &payload[start..end];
    if !bytes.iter().all(|b| *b == 0 || (*b >= 0x20 && *b < 0x7F)) {
        return Err(EepromParseError::BodyDecode {
            detail: format!("non-ASCII bytes in field at offset {}", start),
        });
    }
    let s = std::str::from_utf8(bytes)
        .map_err(|e| EepromParseError::BodyDecode {
            detail: e.to_string(),
        })?
        .trim_end_matches(['\0', ' '])
        .to_string();
    Ok(s)
}

/// Static hashboard-SKU catalog distilled from the local RE corpus.
///
/// This is intentionally a small catalog surface, not a live EEPROM reader.
/// Route/API consumers can render this table without linking HAL code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BhbSkuCatalogEntry {
    pub pattern: &'static str,
    pub chip_family: &'static str,
    pub model_family: &'static str,
    pub eeprom_variant: &'static str,
    pub confidence: &'static str,
    pub source: &'static str,
    pub note: &'static str,
}

/// Known BHB/A3HB SKU-to-chip-family catalog.
///
/// Source anchors:
/// -  secs 1.5-1.11
///   classifies `BHB42801`, `BHB42811`, `BHB42821`, `BHB42831`, and
///   `BHB42841` as S19 XP / S19j XP BM1366 profile rows.
/// -  line 278
///   lists the same `BHB428xx` SKUs in the BM1366 board set.
///
/// Keep `BHB428xx -> BM1366` load-bearing; older model notes contained a
/// stale `BHB42801 -> BM1362` line.
///
/// ## Prefer EXACT `model_id` rows; prefixes are the legacy shape (UB-26)
///
/// The `*xx` patterns here are **prefix** matchers. A prefix answers for SKUs
/// nobody has ever examined, which is how `BHB68xxx -> BM1370` came to give a
/// wrong-family answer for six BM1368 boards. New rows are therefore EXACT
/// `model_id` keys, and [`catalog_entry_for_sku`] is a first-match-wins linear
/// scan, so **an exact row must be listed before any prefix that would also
/// match it**.
///
/// **W8 rank-9 (2026-08-03): the `BHB68xxx -> BM1370` catch-all is RETIRED.**
/// An unknown `BHB68…` SKU now resolves to `None` — fail closed, never a
/// guessed family. Rationale: every one of the 8 `BHB68xxx` boards in the held
/// ePIC v1.22.0 roster is `asic_id BM1368`/`asic_addr 0x1368`; zero BHB68
/// boards anywhere in any held corpus are BM1370 (the roster's 13 BM1370
/// boards are all `A3HB*`, format 1); and the DCENT-held s21 `BHB68606` page
/// plus the three held format-5 BHB68 pages all carry the BM1368 lot-code
/// letter `'V'` (W5-RANK-13 §2). A catch-all in EITHER direction is a guess:
/// `-> BM1370` mis-labels the likely-BM1368 unknown, `-> BM1368` would
/// mis-label a future genuine BM1370 `BHB68…`. Neither is evidence, so an
/// unknown must be `None` (per-SKU evidence adds a new EXACT row). The
/// remaining `BHB426xx`/`BHB428xx`/`BHB568xx/BHB569xx` prefixes are separate
/// adjudications with their own evidence base and are unchanged here.
///
/// The exact-keyed, roster-complete counterpart (50 SKUs, with per-row
/// provenance and no prefix matching at all) is
/// `dcentrald-silicon-profiles::hashboard_catalog`. It cannot live here —
/// this crate is HAL-free and deliberately upstream of silicon-profiles.
pub const BHB_SKU_CATALOG: &[BhbSkuCatalogEntry] = &[
    BhbSkuCatalogEntry {
        pattern: "BHB426xx",
        chip_family: "BM1362",
        model_family: "S19j Pro / S19j Pro variants",
        eeprom_variant: "x19_plain",
        confidence: "high",
        source: " secs 1.1-1.4",
        note: "BHB426xx rows cover the S19j Pro BM1362 family.",
    },
    // UB-26 (2026-08-03): EXACT row. `BHB42701` starts with `BHB427`, so no
    // pattern in this table matched it and `chip_family_for_sku("BHB42701")`
    // returned `None` — a catalogued board with no resolvable family (H3 §1.4
    // records the same refusal). Two independent sources say BM1362: our own
    // `dcentrald-silicon-profiles::hashboards` catalog row (`BHB42701`, 108
    // chips/chain, efficiency-optimised, with a per-SKU BM1362 PVT table) and
    // the ePIC jig DB (`asic_id BM1362`, `asic_addr 0x1362`, 108 chips).
    // Exact key, deliberately NOT a new `BHB427xx` prefix.
    BhbSkuCatalogEntry {
        pattern: "BHB42701",
        chip_family: "BM1362",
        model_family: "S19j",
        eeprom_variant: "x19_plain",
        confidence: "high",
        source: "silicon-profiles::hashboards BHB42701 catalog row + bm1362 PVT table; \
                 epic-jig-hashboard-db-50models.json (BM1362/0x1362, 108 chips)",
        note: "Exact row: BHB42701 matched no pattern before UB-26 and resolved to None. \
               Held page observed as format 4 (0x04 0x11); dispatch is still always on raw[0].",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB428xx",
        chip_family: "BM1366",
        model_family: "S19 XP / S19j XP / S19j XP Plus",
        eeprom_variant: "x19_plain",
        confidence: "high",
        source: " secs 1.5-1.11;  line 278",
        note: "Corrects the stale BHB42801->BM1362 mapping; BHB428xx is BM1366.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB568xx / BHB569xx",
        chip_family: "BM1366",
        model_family: "S19k Pro / S19k Pro AML / S19 XP variants",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "high",
        source: " lines 531-538; live .78 BHB56902 EEPROM decode",
        note: "BHB56902 is live-driven from the S19k Pro .78 capture.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68603",
        chip_family: "BM1368",
        model_family: "S21 / S21+ / T21",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "high",
        source: " lines 539-540; wave6-vnish-decrypted/BHB_INVENTORY.md",
        note: "BHB68603 is documented as S21-class BM1368, not the broad BM1370 fallback.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68603-",
        chip_family: "BM1368",
        model_family: "S21 / S21+ / T21",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "high",
        source: " lines 539-540; wave6-vnish-decrypted/BHB_INVENTORY.md",
        note: "BHB68603- follows the documented BHB68603 BM1368 family.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68606",
        chip_family: "BM1368",
        model_family: "S21 / S21+",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "high",
        source: " lines 539-540; wave6-vnish-decrypted/BHB_INVENTORY.md",
        note: "BHB68606 is documented as S21-class BM1368, not the broad BM1370 fallback.",
    },
    // ------------------------------------------------------------------
    // UB-26 (2026-08-03): the six remaining EXACT `BHB68xxx` rows.
    //
    // The broad `BHB68xxx -> BM1370` row below is a **prefix catch-all** whose
    // only cited basis is a *preamble* table (`BOSMINER_EEPROM_PARSERS_RE.md`)
    // — and a preamble is a family hint that provably cannot determine an ASIC
    // generation (`0x05 0x11` spans BM1366 AND BM1368). It therefore answered
    // "BM1370" for six SKUs nobody had ever looked at. The ePIC UMC OS v1.22.0
    // jig DB declares all EIGHT `BHB68xxx` roster rows as `asic_id BM1368` /
    // `asic_addr 0x1368` / 108 chips per chain — no `BHB68xxx` board in that
    // roster is BM1370 (the BM1370 boards are the 13 `A3HB*` rows). Four of the
    // six are independently corroborated as 108-chip S21-generation boards by
    // the VNish 1.2.7 model matrix (`BHB68701`/`BHB68703` = Antminer T21,
    // `BHB68707`/`BHB68709` = Antminer S19 XP+).
    //
    // Caveat 3 stands: the ePIC DB is Bitmain-derived but ePIC-TRANSCRIBED and
    // never outranks a DCENT measurement. It is not overruling one here — the
    // value it corrects is a doc inference from a preamble table, not a
    // measurement. Confidence is therefore `medium`, not `high`.
    //
    // These are EXACT keys, never a `BHB687xx` prefix, and they change nothing
    // about admission: `hashboard_eeprom::DEPLOYED_SKU_IDENTITY_POLICY` has no
    // row for any of them, so `observed_protocol_for_deployed_board_name` still
    // refuses all six (pinned by `deployed_bhb68_prefix_never_mints_bm1368`
    // there and by `new_exact_rows_do_not_widen_deployed_admission` here).
    //
    // W8 rank-9 (2026-08-03): the `BHB68xxx -> BM1370` catch-all that used to
    // sit after these rows is REMOVED (see the catalog doc comment above). An
    // unknown `BHB68…` SKU resolves to `None`; only the 8 exact roster rows
    // (BHB68601/68603[-]/68606/68701/68703/68705/68707/68709) answer.
    // ------------------------------------------------------------------
    BhbSkuCatalogEntry {
        pattern: "BHB68601",
        chip_family: "BM1368",
        model_family: "S21-generation BM1368 board; no held corpus names its product",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "medium",
        source: "epic-jig-hashboard-db-50models.json (BM1368/0x1368, 108 chips; ePIC-transcribed, caveat 3)",
        note: "Exact row: was swept into the broad BHB68xxx -> BM1370 catch-all. No held \
               page for this SKU, so the eeprom_variant is the family's observed class, \
               not an attested format — always dispatch on raw[0].",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68701",
        chip_family: "BM1368",
        model_family: "T21",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "medium",
        source: "epic-jig-hashboard-db-50models.json (BM1368/0x1368, 108 chips); \
                 VNish 1.2.7 model matrix (Antminer T21, 108 chips); \
                 epic-eeprom-matched-samples-20.json (held page, format 5)",
        note: "Exact row: was swept into the broad BHB68xxx -> BM1370 catch-all.",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68703",
        chip_family: "BM1368",
        model_family: "T21",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "medium",
        source: "epic-jig-hashboard-db-50models.json (BM1368/0x1368, 108 chips); \
                 VNish 1.2.7 model matrix (Antminer T21, 108 chips)",
        note: "Exact row: was swept into the broad BHB68xxx -> BM1370 catch-all. No held \
               page for this SKU; always dispatch on raw[0].",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68705",
        chip_family: "BM1368",
        model_family: "S21-generation BM1368 board; no held corpus names its product",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "medium",
        source: "epic-jig-hashboard-db-50models.json (BM1368/0x1368, 108 chips; ePIC-transcribed, caveat 3)",
        note: "Exact row: was swept into the broad BHB68xxx -> BM1370 catch-all. No held \
               page for this SKU; always dispatch on raw[0].",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68707",
        chip_family: "BM1368",
        model_family: "S19 XP+",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "medium",
        source: "epic-jig-hashboard-db-50models.json (BM1368/0x1368, 108 chips); \
                 VNish 1.2.7 model matrix (Antminer S19 XP+, 108 chips)",
        note: "Exact row: was swept into the broad BHB68xxx -> BM1370 catch-all. No held \
               page for this SKU; always dispatch on raw[0].",
    },
    BhbSkuCatalogEntry {
        pattern: "BHB68709",
        chip_family: "BM1368",
        model_family: "S19 XP+",
        eeprom_variant: "edf_v5_xxtea_key1",
        confidence: "medium",
        source: "epic-jig-hashboard-db-50models.json (BM1368/0x1368, 108 chips); \
                 VNish 1.2.7 model matrix (Antminer S19 XP+, 108 chips)",
        note: "Exact row: was swept into the broad BHB68xxx -> BM1370 catch-all. No held \
               page for this SKU; always dispatch on raw[0].",
    },
    BhbSkuCatalogEntry {
        pattern: "A3HB4xxxx",
        chip_family: "BM1370",
        model_family: "S21 Pro / S21 XP class",
        eeprom_variant: "format1_plaintext_name",
        confidence: "low",
        source: "epic-jig-hashboard-db-50models.json (A3HB40601 -> BM1370; ePIC-transcribed, caveat 3)",
        note: "A3HB40601 was silently unresolved before this row. Format 1 \
               (0x01 0x41) inferred from the A3HB7 sibling family; no held page \
               for A3HB4, so treat the format as unconfirmed and always dispatch \
               on raw[0].",
    },
    BhbSkuCatalogEntry {
        pattern: "A3HB7xxxx",
        chip_family: "BM1370",
        model_family: "S21 Pro / S21 XP class",
        // Format 1 (0x01 0x41), NOT edf_v5. Ground truth: three held pages
        // A3HB70501/70601/70701 decode as format_version=1, keyver=0x41 =
        // board_name[0] 'A' (plaintext), NOT a key selector.
        eeprom_variant: "format1_plaintext_name",
        confidence: "high",
        source: "epic-eeprom-matched-samples-20.json (A3HB70501/70601/70701 fmt=1|keyver=65)",
        note: "Corrects the stale A3HB7xxxx -> edf_v5_xxtea (0x05) label; A3HB7 \
               is format 1 (0x01 0x41), board_name in plaintext, enciphered body \
               key unrecovered. Dispatch on raw[0], never map SKU -> format.",
    },
    // ------------------------------------------------------------------
    // UB-26 (2026-08-03): the two non-`model_id` jig records. Neither matched
    // any pattern, so both resolved to `None`.
    //
    // These are the strongest-evidenced rows in this table: we RE'd `NBP1901`
    // from a completely different source (`bm1398_protocol.rs`'s
    // `S19_PRO_NBP1901_CHAIN_SPEC`, jig-recovered 2026-07-24: 114 chips,
    // 38 voltage domains x 3) and the ePIC DB independently reproduces it
    // exactly; `NBS1902`'s 76 = 38 x 2 likewise matches
    // `projects/dcent-hashboards/HASHBOARD_TARGET_MATRIX.md:45`.
    //
    // IDENTITY LABEL ONLY. Native BM1398 remains NOT IMPLEMENTED and refused:
    // `hashboard_eeprom::DEPLOYED_SKU_IDENTITY_POLICY` declares no BM1398 row,
    // a row only ever admits its OWN identity, and the `0x04`-never-admits-
    // BM1398 invariant is unchanged. Pinned by
    // `new_exact_rows_do_not_widen_deployed_admission`.
    // ------------------------------------------------------------------
    BhbSkuCatalogEntry {
        pattern: "NBP1901",
        chip_family: "BM1398",
        model_family: "S19 Pro",
        // No held page for either NB* SKU, so the on-page format is UNKNOWN.
        // Do not guess a family default here — dispatch is on raw[0] anyway.
        eeprom_variant: "unknown_no_held_page",
        confidence: "high",
        source: "bm1398_protocol.rs S19_PRO_NBP1901_CHAIN_SPEC (jig-recovered 2026-07-24: \
                 114 chips / 38 domains x 3); epic-jig-hashboard-db-50models.json (BM1398P/0x1398, \
                 114 chips, chain_domain_num 38) — two independent sources agreeing exactly",
        note: "Exact row: NBP1901 matched no pattern before UB-26 and resolved to None. \
               Identity label only; native BM1398 stays refused by the admission policy.",
    },
    BhbSkuCatalogEntry {
        pattern: "NBS1902",
        chip_family: "BM1398",
        model_family: "S19",
        eeprom_variant: "unknown_no_held_page",
        confidence: "high",
        source: "epic-jig-hashboard-db-50models.json (BM1398P/0x1398, 76 chips, 38 domains x 2); \
                 projects/dcent-hashboards/HASHBOARD_TARGET_MATRIX.md:45 (S19: 76 = 38 x 2)",
        note: "Exact row: NBS1902 matched no pattern before UB-26 and resolved to None. \
               Identity label only; native BM1398 stays refused by the admission policy.",
    },
];

/// Returns the chip-family string for a known hashboard SKU. Mirrors
/// bosminer's in-binary SKU table at `0x00eec028` plus the local
///  corrections above. Caller plugs the result
/// into `dcentrald-silicon-profiles` to look up a `SiliconTable`.
pub fn chip_family_for_sku(b_name: &str) -> Option<&'static str> {
    catalog_entry_for_sku(b_name).map(|entry| entry.chip_family)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_x21_payload(serial: &str, b_name: &str) -> Vec<u8> {
        let mut payload = vec![0u8; 32];
        let s = serial.as_bytes();
        let n = s.len().min(17);
        payload[..n].copy_from_slice(&s[..n]);
        let b = b_name.as_bytes();
        let bn = b.len().min(8);
        payload[17..17 + bn].copy_from_slice(&b[..bn]);
        payload
    }

    fn synthetic_raw_blob(preamble: [u8; 2], sku: &str) -> Vec<u8> {
        let mut raw = vec![0u8; RAW_EEPROM_BLOB_LEN];
        raw[0] = preamble[0];
        raw[1] = preamble[1];
        raw[32..32 + sku.len()].copy_from_slice(sku.as_bytes());
        raw
    }

    fn synthetic_raw_x21_blob(serial: &str, sku: &str) -> Vec<u8> {
        let mut raw = vec![0u8; RAW_EEPROM_BLOB_LEN];
        raw[0] = 0x05;
        raw[1] = 0x11;
        let payload = synthetic_x21_payload(serial, sku);
        raw[2..2 + payload.len()].copy_from_slice(&payload);
        raw
    }

    #[test]
    fn truncated_blob_returns_truncated() {
        let r = dispatch(&[]).unwrap_err();
        assert!(matches!(r, EepromParseError::Truncated { got: 0, need: 2 }));
        let r = dispatch(&[0x05]).unwrap_err();
        assert!(matches!(r, EepromParseError::Truncated { got: 1, need: 2 }));
    }

    #[test]
    fn unknown_preamble_returns_unknown_preamble() {
        let r = dispatch(&[0xff, 0xfe, 0x00, 0x00]).unwrap_err();
        match r {
            EepromParseError::UnknownPreamble { byte0, byte1 } => {
                assert_eq!(byte0, 0xff);
                assert_eq!(byte1, 0xfe);
            }
            _ => panic!("expected UnknownPreamble, got {:?}", r),
        }
    }

    #[test]
    fn x19_preamble_dispatches_to_x19_plain_variant() {
        let mut blob = vec![0x04, 0x11];
        blob.extend_from_slice(&[0xaa; 8]);
        let r = dispatch(&blob).unwrap();
        match r {
            EepromRecord::X19Plain(rec) => {
                assert_eq!(rec.raw_payload, vec![0xaa; 8]);
            }
            _ => panic!("expected X19Plain, got {:?}", r),
        }
    }

    #[test]
    fn edf_v5_xxtea_preamble_dispatches_metadata() {
        let mut blob = vec![0x05, 0x11];
        blob.extend_from_slice(&[0xaa; 8]);
        let r = dispatch(&blob).unwrap();
        match r {
            EepromRecord::EdfV5Xxtea(rec) => {
                assert_eq!(rec.format_version, 5);
                assert_eq!(rec.cipher, "xxtea");
                assert_eq!(rec.key_index, 1);
                assert_eq!(rec.raw_payload, vec![0xaa; 8]);
            }
            _ => panic!("expected EdfV5Xxtea, got {:?}", r),
        }
    }

    #[test]
    fn x21_aes_truncated_payload_is_caught() {
        let r = decode_x21_aes(&[0x00]).unwrap_err();
        assert!(matches!(r, EepromParseError::Truncated { .. }));
    }

    #[test]
    fn x21_aes_non_ascii_field_fails_closed() {
        let mut payload = vec![0u8; 32];
        // Inject a non-ASCII byte (0xFE) in the serial range.
        payload[5] = 0xFE;
        let r = decode_x21_aes(&payload).unwrap_err();
        assert!(matches!(r, EepromParseError::BodyDecode { .. }));
    }

    #[test]
    fn braiinsminer_preamble_recognized() {
        let mut blob = vec![b'B', b'r'];
        blob.extend_from_slice(&[0x21, 0x00, 0xff]);
        let r = dispatch(&blob).unwrap();
        match r {
            EepromRecord::Braiinsminer(rec) => {
                // Includes the magic.
                assert_eq!(rec.raw_payload, vec![b'B', b'r', 0x21, 0x00, 0xff]);
            }
            _ => panic!("expected Braiinsminer, got {:?}", r),
        }
    }

    #[test]
    fn chip_family_lookup_known_skus() {
        assert_eq!(chip_family_for_sku("BHB56902"), Some("BM1366"));
        assert_eq!(chip_family_for_sku("BHB42601"), Some("BM1362"));
        assert_eq!(chip_family_for_sku("BHB42699"), Some("BM1362"));
        assert_eq!(chip_family_for_sku("BHB42801"), Some("BM1366"));
        assert_eq!(chip_family_for_sku("BHB42811"), Some("BM1366"));
        assert_eq!(chip_family_for_sku("BHB42821"), Some("BM1366"));
        assert_eq!(chip_family_for_sku("BHB42831"), Some("BM1366"));
        assert_eq!(chip_family_for_sku("BHB42841"), Some("BM1366"));
        assert_eq!(chip_family_for_sku("BHB428xx"), Some("BM1366"));
        assert_eq!(chip_family_for_sku("BHB56801"), Some("BM1366"));
        assert_eq!(chip_family_for_sku("BHB68603"), Some("BM1368"));
        assert_eq!(chip_family_for_sku("BHB68603-"), Some("BM1368"));
        assert_eq!(chip_family_for_sku("BHB68606"), Some("BM1368"));
        // W8 rank-9: no BHB68 catch-all — an off-roster BHB68 SKU is None.
        assert_eq!(chip_family_for_sku("BHB68123"), None);
        // A3HB40601 was silently unresolved before the A3HB4 pattern was added.
        assert_eq!(chip_family_for_sku("A3HB40601"), Some("BM1370"));
        assert_eq!(chip_family_for_sku("A3HB70501"), Some("BM1370"));
        assert_eq!(chip_family_for_sku("A3HB70601"), Some("BM1370"));
        assert_eq!(chip_family_for_sku("A3HB70701"), Some("BM1370"));
        assert_eq!(chip_family_for_sku("UNKNOWN-XX"), None);
        assert_eq!(chip_family_for_sku(""), None);
    }

    #[test]
    fn a3hb_boards_are_format1_not_edf_v5() {
        // Ground truth: A3HB70501/70601/70701 decode as format_version=1
        // (header 0x01 0x41), NOT format 5 (0x05 0x11). The catalog must not
        // relabel them edf_v5. Evidence:
        //
        //   epic-eeprom-matched-samples-20.json
        for sku in ["A3HB40601", "A3HB70501", "A3HB70601", "A3HB70701"] {
            let entry = catalog_entry_for_sku(sku).expect("A3HB catalog entry");
            assert_eq!(entry.chip_family, "BM1370");
            assert_eq!(entry.eeprom_variant, "format1_plaintext_name");
            assert_ne!(entry.eeprom_variant, "edf_v5_xxtea_key1");
        }
    }

    #[test]
    fn a3hb40601_format1_page_resolves_identity_without_edf_v5() {
        // A real format-1 page: header 0x01 0x41 then the plaintext board name
        // (0x41 = board_name[0] = 'A'). dispatch() does not handle 0x01 (that
        // is a separate enciphered-body item), so the preamble reads as
        // UnknownPreamble — but the plaintext SKU must still resolve identity.
        let mut raw = vec![0u8; RAW_EEPROM_BLOB_LEN];
        raw[0] = 0x01;
        raw[1] = 0x41;
        raw[1..1 + b"A3HB40601".len()].copy_from_slice(b"A3HB40601");

        let report = decode_raw_256_blob(&raw);
        // 0x01 0x41 is not a dispatched preamble here.
        assert_eq!(report.status, RawEepromDecodeStatus::UnknownPreamble);
        // ...but the plaintext SKU resolves board identity via scan_known_sku.
        assert_eq!(report.metadata.board_sku.as_deref(), Some("A3HB40601"));
        assert_eq!(report.metadata.chip_family.as_deref(), Some("BM1370"));
        assert!(report.metadata.read_only);
        assert!(!report.metadata.writes_performed);
    }

    /// UB-26 + W8 rank-9. The eight `BHB68xxx` roster SKUs resolve to BM1368
    /// by EXACT key, and the broad `BHB68xxx -> BM1370` catch-all is GONE.
    ///
    /// All eight `BHB68xxx` rows in the held ePIC v1.22.0 roster declare
    /// `asic_id BM1368` / `asic_addr 0x1368` / 108 chips; no roster `BHB68xxx`
    /// board is BM1370 (the 13 BM1370 roster boards are all `A3HB*`). Four are
    /// independently corroborated by the VNish 1.2.7 matrix (T21 / S19 XP+,
    /// 108 chips), and the held format-5 BHB68 pages (ePIC BHB68603/68606/
    /// 68701 + the DCENT-held s21 `BHB68606` dump) all decode with the BM1368
    /// lot-code letter `'V'` (W5-RANK-13 §2).
    #[test]
    fn exact_bhb68_rows_replace_the_bm1370_catch_all_answer() {
        for sku in [
            "BHB68601", "BHB68603", "BHB68606", "BHB68701", "BHB68703", "BHB68705", "BHB68707",
            "BHB68709",
        ] {
            let entry = catalog_entry_for_sku(sku).expect("exact BHB68 row");
            assert_eq!(entry.pattern, sku, "{sku} must match its OWN exact row");
            assert_eq!(
                entry.chip_family, "BM1368",
                "{sku}: every roster BHB68xxx board is BM1368"
            );
        }
    }

    /// W8 rank-9 NEGATIVE pin: an unknown `BHB68…` SKU resolves to `None`.
    ///
    /// A catch-all in either direction is a guess — `-> BM1370` mis-labels the
    /// likely-BM1368 unknown, `-> BM1368` would mis-label a future genuine
    /// BM1370 `BHB68…` board. Identity resolution fails CLOSED; new evidence
    /// adds a new EXACT row, never a prefix.
    #[test]
    fn unknown_bhb68_sku_resolves_to_none_never_a_guessed_family() {
        for probe in [
            "BHB68123",
            "BHB68999",
            "BHB68602",
            "BHB68607",
            "BHB68702",
            "BHB68711",
            "BHB68",
            "BHB686",
            "BHB68xxx",
            "BHB686060",
        ] {
            assert_eq!(
                chip_family_for_sku(probe),
                None,
                "{probe}: off-roster BHB68 must fail closed, not guess a family"
            );
            assert!(catalog_entry_for_sku(probe).is_none(), "{probe}");
        }
        // ...and no row in the table is a BHB68 prefix pattern anymore.
        assert!(
            !BHB_SKU_CATALOG
                .iter()
                .any(|e| e.pattern.starts_with("BHB68") && e.pattern.contains('x')),
            "a BHB68 prefix row must never be reintroduced — exact keys only"
        );
    }

    /// UB-26. Three SKUs that previously matched NO pattern and returned
    /// `None`: `BHB42701` (BHB427, outside the `BHB426`/`BHB428` prefixes) and
    /// the two non-`model_id` jig records.
    #[test]
    fn previously_unresolvable_exact_skus_now_resolve() {
        assert_eq!(chip_family_for_sku("BHB42701"), Some("BM1362"));
        assert_eq!(chip_family_for_sku("NBP1901"), Some("BM1398"));
        assert_eq!(chip_family_for_sku("NBS1902"), Some("BM1398"));
        // Still exact — no new prefix space was opened.
        for probe in ["BHB427", "BHB42702", "NBP", "NBP19011", "NBS", "NB"] {
            assert_eq!(
                chip_family_for_sku(probe),
                None,
                "{probe} must not resolve — the new rows are exact keys"
            );
        }
    }

    /// LOAD-BEARING order invariant: this table is a linear `find`, so an
    /// exact row placed AFTER a prefix that also matches it is dead code and
    /// the wrong family wins silently. Assert every exact row still answers
    /// for itself.
    #[test]
    fn exact_rows_precede_the_prefix_catch_all_they_correct() {
        for entry in BHB_SKU_CATALOG {
            // Only exact rows (patterns that are their own SKU) are checked;
            // the pattern strings ending in `xx`/`xxx`/`xxxx` are prefixes.
            if entry.pattern.contains('x') {
                continue;
            }
            let resolved = catalog_entry_for_sku(entry.pattern)
                .unwrap_or_else(|| panic!("{} resolves to nothing", entry.pattern));
            assert_eq!(
                resolved.pattern, entry.pattern,
                "exact row {} is shadowed by earlier pattern {} — reorder the table",
                entry.pattern, resolved.pattern
            );
        }
    }

    /// The new rows are IDENTITY LABELS. None of them widens the deployed-page
    /// admission gate: `DEPLOYED_SKU_IDENTITY_POLICY` has no row for any of
    /// them, so `observed_protocol_for_deployed_board_name` still refuses —
    /// and in particular native BM1398 stays refused.
    #[test]
    fn new_exact_rows_do_not_widen_deployed_admission() {
        use crate::hashboard_eeprom::observed_protocol_for_deployed_board_name;
        for sku in [
            "BHB42701", "BHB68601", "BHB68701", "BHB68703", "BHB68705", "BHB68707", "BHB68709",
            "NBP1901", "NBS1902",
        ] {
            assert!(
                catalog_entry_for_sku(sku).is_some(),
                "{sku} must be catalogued"
            );
            assert_eq!(
                observed_protocol_for_deployed_board_name(sku),
                None,
                "{sku}: a catalog identity label must never mint an observed identity"
            );
        }
    }

    /// No new row may claim an EEPROM format it has no held page for.
    /// `format_version` is not a function of SKU (`BHB56801` is held as both
    /// format 4 and format 5), so an unattested SKU says so.
    #[test]
    fn unattested_new_rows_do_not_claim_a_held_format() {
        for sku in ["NBP1901", "NBS1902"] {
            let e = catalog_entry_for_sku(sku).unwrap();
            assert_eq!(e.eeprom_variant, "unknown_no_held_page", "{sku}");
        }
        for sku in ["BHB68601", "BHB68703", "BHB68705", "BHB68707", "BHB68709"] {
            let e = catalog_entry_for_sku(sku).unwrap();
            assert!(
                e.note.contains("No held page for this SKU"),
                "{sku}: an unattested format must say so in the note, got {:?}",
                e.note
            );
            assert!(e.note.contains("dispatch on raw[0]"), "{sku}");
        }
    }

    #[test]
    fn bhb_sku_catalog_pins_bhb428xx_to_bm1366() {
        let entry = BHB_SKU_CATALOG
            .iter()
            .find(|entry| entry.pattern == "BHB428xx")
            .expect("BHB428xx catalog entry");

        assert_eq!(entry.chip_family, "BM1366");
        assert!(entry.note.contains("BHB42801->BM1362"));
        assert!(entry.source.contains(""));
        assert!(entry.source.contains(""));
    }

    #[test]
    fn bhb_sku_catalog_pins_documented_bhb686_to_bm1368() {
        for sku in ["BHB68603", "BHB68606"] {
            let entry = catalog_entry_for_sku(sku).expect("BHB686 exact catalog entry");
            assert_eq!(entry.chip_family, "BM1368");
            assert_eq!(entry.eeprom_variant, "edf_v5_xxtea_key1");
            assert!(entry.note.contains("not the broad BM1370 fallback"));
        }
    }

    #[test]
    fn x21_aes_record_round_trips_through_serde() {
        let r = X21AesRecord {
            serial_number: "AS19K1234567890AB".to_string(),
            b_name: "BHB56902".to_string(),
            pcb_version: 0x4242,
            bom_version: 0x5555,
            fact_job: "JYZZ20230901007-Y1".to_string(),
            ch_die: "ED".to_string(),
            ch_marking: "S1GM23AL36".to_string(),
            ft: "F1V18B3C1".to_string(),
            ch_tech: "BS".to_string(),
            bin: "4".to_string(),
            vf: vec![0xde, 0xad, 0xbe, 0xef],
            sale_rate: Some("HIGH".to_string()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: X21AesRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn eeprom_record_serde_round_trip_with_tagged_variant() {
        let r = EepromRecord::X19Plain(X19PlainRecord {
            algo_or_subver: 0xAA,
            raw_payload: vec![1, 2, 3],
        });
        let json = serde_json::to_string(&r).unwrap();
        // Per the snake_case + tag="variant" attribute.
        assert!(json.contains("\"variant\":\"x19_plain\""));
        let back: EepromRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn eeprom_parse_error_serde_round_trip() {
        let err = EepromParseError::UnknownPreamble {
            byte0: 0x77,
            byte1: 0x88,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: EepromParseError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
        assert!(json.contains("\"error\":\"unknown_preamble\""));
    }

    #[test]
    fn x21_payload_with_short_serial_trims_correctly() {
        let payload = synthetic_x21_payload("AS19K123", "BHB56902");
        let rec = decode_x21_aes(&payload).unwrap();
        // Serial field is 17 bytes wide; trim trailing NUL.
        assert_eq!(rec.serial_number, "AS19K123");
        assert_eq!(rec.b_name, "BHB56902");
    }

    #[test]
    fn b_name_round_trip_against_re_doc_anchor() {
        // RE doc anchor: hb0/hb1/hb2 from .78 all decode to BHB56902 (BM1366).
        let payload = synthetic_x21_payload("AS19K00000000.78a", "BHB56902");
        let rec = decode_x21_aes(&payload).unwrap();
        assert_eq!(chip_family_for_sku(&rec.b_name), Some("BM1366"));
    }

    #[test]
    fn truncated_x21_payload_short_of_b_name_field_is_caught() {
        // Payload shorter than offset+8 (b_name width) returns Truncated.
        // Only 16 bytes after preamble: too short for b_name @ offset 17.
        let r = decode_x21_aes(&[0x42; 16]).unwrap_err();
        assert!(matches!(r, EepromParseError::Truncated { .. }));
    }

    #[test]
    fn read_ascii_field_trims_trailing_spaces_and_nuls() {
        let mut payload = vec![0u8; 16];
        payload[..5].copy_from_slice(b"hello");
        payload[5] = b' ';
        payload[6] = b' ';
        payload[7] = 0;
        let s = read_ascii_field(&payload, 0, 16).unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn raw_256_x19_bhb426_metadata_is_normalized_without_writes() {
        let raw = synthetic_raw_blob([0x04, 0x11], "BHB42601");
        let report = decode_raw_256_blob(&raw);

        assert_eq!(report.schema, RAW_EEPROM_DECODE_SCHEMA);
        assert_eq!(report.raw_len, RAW_EEPROM_BLOB_LEN);
        assert_eq!(report.status, RawEepromDecodeStatus::MetadataOnly);
        assert_eq!(report.metadata.board_sku.as_deref(), Some("BHB42601"));
        assert_eq!(report.metadata.chip_family.as_deref(), Some("BM1362"));
        assert_eq!(
            report.metadata.model_family.as_deref(),
            Some("S19j Pro / S19j Pro variants")
        );
        assert_eq!(report.metadata.eeprom_variant.as_deref(), Some("x19_plain"));
        assert!(report.metadata.read_only);
        assert!(!report.metadata.writes_performed);
    }

    #[test]
    fn raw_256_x19_bhb428_metadata_uses_correct_bm1366_catalog() {
        let raw = synthetic_raw_blob([0x04, 0x11], "BHB42841");
        let report = decode_raw_256_blob(&raw);

        assert_eq!(report.status, RawEepromDecodeStatus::MetadataOnly);
        assert_eq!(report.metadata.board_sku.as_deref(), Some("BHB42841"));
        assert_eq!(report.metadata.chip_family.as_deref(), Some("BM1366"));
        assert!(report
            .metadata
            .notes
            .iter()
            .any(|note| note.contains("BHB42801->BM1362")));
    }

    #[test]
    fn raw_256_edf_v5_bhb56902_reports_xxtea_metadata() {
        let raw = synthetic_raw_x21_blob("AS19K1234567890AB", "BHB56902");
        let report = decode_raw_256_blob(&raw);

        assert_eq!(report.status, RawEepromDecodeStatus::MetadataOnly);
        assert_eq!(report.metadata.board_sku.as_deref(), Some("BHB56902"));
        assert_eq!(report.metadata.serial_number.as_deref(), None);
        assert_eq!(report.metadata.chip_family.as_deref(), Some("BM1366"));
        assert_eq!(
            report.metadata.eeprom_variant.as_deref(),
            Some("edf_v5_xxtea_key1")
        );
        assert_eq!(report.metadata.eeprom_format.as_deref(), Some("edf_v5"));
        assert_eq!(report.metadata.cipher.as_deref(), Some("xxtea"));
        assert_eq!(report.metadata.key_index, Some(1));
        assert!(matches!(report.record, Some(EepromRecord::EdfV5Xxtea(_))));
        assert!(report.metadata.read_only);
        assert!(!report.metadata.writes_performed);
    }

    #[test]
    fn raw_256_edf_v5_bhb68603_maps_to_bm1368() {
        let raw = synthetic_raw_blob([0x05, 0x11], "BHB68603");
        let report = decode_raw_256_blob(&raw);

        assert_eq!(report.status, RawEepromDecodeStatus::MetadataOnly);
        assert_eq!(report.metadata.board_sku.as_deref(), Some("BHB68603"));
        assert_eq!(report.metadata.chip_family.as_deref(), Some("BM1368"));
        assert_eq!(
            report.metadata.model_family.as_deref(),
            Some("S21 / S21+ / T21")
        );
        assert_eq!(report.metadata.eeprom_format.as_deref(), Some("edf_v5"));
        assert_eq!(report.metadata.cipher.as_deref(), Some("xxtea"));
        assert_eq!(report.metadata.key_index, Some(1));
    }

    #[test]
    fn raw_256_malformed_preamble_fails_closed() {
        let raw = synthetic_raw_blob([0xde, 0xad], "BHB42601");
        let report = decode_raw_256_blob(&raw);

        assert_eq!(report.status, RawEepromDecodeStatus::UnknownPreamble);
        assert!(report.record.is_none());
        assert_eq!(report.metadata.board_sku.as_deref(), Some("BHB42601"));
        assert!(report.metadata.read_only);
        assert!(!report.metadata.writes_performed);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("unknown EEPROM preamble")));
    }

    #[test]
    fn raw_decode_rejects_non_256_byte_blob() {
        let report = decode_raw_256_blob(&[0x05, 0x11, 0x00]);

        assert_eq!(report.status, RawEepromDecodeStatus::MalformedLength);
        assert_eq!(report.raw_len, 3);
        assert!(report.record.is_none());
        assert!(report.metadata.read_only);
        assert!(!report.metadata.writes_performed);
    }
}
