//! FR-1.28 (251010) stock S19k Pro `.bmu` firmware container parser
//! (desk RE, ).
//!
//! The FR-1.28 update image is NOT the legacy single-image `0x26 + PEM`
//! BMU: it is a 3-variant container. Each variant blob still leads with
//! `26 01`, a `20251010` build date, and an RSA public-key PEM, but the
//! container itself has its own magic and TOC.
//!
//! Container layout (little-endian, evidence: `FR-1.28(251010-S19k Pro).bmu`,
//! sha256 `46c6f682e7f0a88a65d5be239409583fdb6d6df59d2e2a92a81e50ce47d56c1c`,
//! 44,604,212 bytes):
//!
//! ```text
//! 0x00 u32  magic 0xABABABAB
//! 0x08 u32  toc_offset (0x24)
//! 0x0C u32  entry_count (3)
//! 0x10 u32  header_entry_len (0xAC)
//! 0x14 u32  blob_base (0x4000)
//! 0x18 u32  build id (0xF00DC230)
//! ```
//!
//! TOC entries (stride 0xAC):
//!
//! ```text
//! +0x00 u32  tag (0a 00 <variant> 11)
//! +0x04 [64] file name ("update.bmu")
//! +0x44 [32] variant name
//! +0x64 [64] product name
//! +0xA4 u32  blob offset
//! +0xA8 u32  blob length
//! ```
//!
//! Blobs tile the file contiguously: AML `0x4000..0xD1DC00`, zynq
//! `0xD1DC00..0x1E68428`, CV `0x1E68428..0x2A89B34` (= file size).

/// Container magic `ab ab ab ab`.
pub const S19K_BMU_TOC_MAGIC: u32 = 0xABAB_ABAB;

/// Header field: TOC entry stride.
pub const S19K_BMU_TOC_ENTRY_STRIDE: usize = 0xAC;

/// FR-1.28 has exactly three control-board variants.
pub const S19K_BMU_FR128_ENTRY_COUNT: usize = 3;

/// FR-1.28 blob base (first blob offset).
pub const S19K_BMU_FR128_BLOB_BASE: u32 = 0x4000;

/// FR-1.28 container build id (`30 c2 0d f0` on disk).
pub const S19K_BMU_FR128_BUILD_ID: u32 = 0xF00D_C230;

/// FR-1.28 whole-file sha256 (evidence pin; the file stays in the
/// operator's Downloads, never in this repo).
pub const S19K_BMU_FR128_SHA256: &str =
    "46c6f682e7f0a88a65d5be239409583fdb6d6df59d2e2a92a81e50ce47d56c1c";

/// FR-1.28 AML variant TOC evidence.
pub const S19K_BMU_FR128_AML: (&str, u32, u32, &str) = (
    "AMLCtrl_BHB56XXX",
    0x4000,
    0xD19C00,
    "3703144bc2b78a27fbdc67d0e88faa18a85e71053539caf89ee44260dd69660b",
);

/// FR-1.28 Zynq variant TOC evidence.
pub const S19K_BMU_FR128_ZYNQ: (&str, u32, u32, &str) = (
    "zynq7007_BHB56XXX",
    0xD1DC00,
    0x114A828,
    "be1e31ad33fba6223a7c4d63dca7f146ca1dd6b79214bb124fe11118768e7024",
);

/// FR-1.28 CV variant TOC evidence.
pub const S19K_BMU_FR128_CV: (&str, u32, u32, &str) = (
    "CVCtrl_BHB56XXX",
    0x1E68428,
    0xC2170C,
    "5774e640df3547c7f59ab9604e61fd847f9621861c7362c1536f65629726cdbf",
);

/// Each variant blob leads with `26 01` before the per-blob id.
pub const S19K_BMU_VARIANT_BLOB_LEAD: [u8; 2] = [0x26, 0x01];

/// Build-date string carried by every FR-1.28 variant blob.
pub const S19K_BMU_FR128_BUILD_DATE: &[u8] = b"20251010";

/// Every variant blob embeds this PEM marker (RSA public key).
pub const S19K_BMU_VARIANT_PEM_MARKER: &[u8] = b"-----BEGIN PUBLIC KEY-----";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kBmuTocEntry {
    pub tag: u32,
    pub file_name: String,
    pub variant: String,
    pub product: String,
    pub blob_offset: u32,
    pub blob_length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kBmuToc {
    pub build_id: u32,
    pub entries: Vec<S19kBmuTocEntry>,
}

fn cstr(buf: &[u8]) -> Result<String, &'static str> {
    let end = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or("bmu TOC name field has no NUL terminator")?;
    let s = std::str::from_utf8(&buf[..end]).map_err(|_| "bmu TOC name is not UTF-8")?;
    if s.is_empty() {
        return Err("bmu TOC name field is empty");
    }
    Ok(s.to_string())
}

fn u32_le(blob: &[u8], at: usize) -> Result<u32, &'static str> {
    let b = blob
        .get(at..at + 4)
        .ok_or("bmu container truncated before u32 field")?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Parse the FR-1.28-style 3-variant `.bmu` container TOC. Blob payloads
/// are NOT decrypted or validated here; this is a structural parse only.
pub fn parse_s19k_bmu_toc(blob: &[u8]) -> Result<S19kBmuToc, &'static str> {
    if blob.len() < 0x20 {
        return Err("bmu container shorter than the fixed header");
    }
    if u32_le(blob, 0)? != S19K_BMU_TOC_MAGIC {
        return Err("bmu container magic is not abababab");
    }
    let toc_offset = u32_le(blob, 0x08)? as usize;
    let entry_count = u32_le(blob, 0x0C)? as usize;
    if entry_count != S19K_BMU_FR128_ENTRY_COUNT {
        return Err("bmu container entry count is not the FR-1.28 three-variant form");
    }
    let build_id = u32_le(blob, 0x18)?;
    let mut entries = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let base = toc_offset + i * S19K_BMU_TOC_ENTRY_STRIDE;
        let end = base + S19K_BMU_TOC_ENTRY_STRIDE;
        let entry_buf = blob
            .get(base..end)
            .ok_or("bmu container truncated inside a TOC entry")?;
        let tag = u32::from_le_bytes([entry_buf[0], entry_buf[1], entry_buf[2], entry_buf[3]]);
        let file_name = cstr(entry_buf.get(0x04..0x44).ok_or("bmu file-name window")?)?;
        let variant = cstr(entry_buf.get(0x44..0x64).ok_or("bmu variant window")?)?;
        let product = cstr(entry_buf.get(0x64..0xA4).ok_or("bmu product window")?)?;
        let blob_offset = u32_le(blob, base + 0xA4)?;
        let blob_length = u32_le(blob, base + 0xA8)?;
        let blob_end = u64::from(blob_offset) + u64::from(blob_length);
        if blob_end > blob.len() as u64 {
            return Err("bmu TOC blob extends past the container end");
        }
        entries.push(S19kBmuTocEntry {
            tag,
            file_name,
            variant,
            product,
            blob_offset,
            blob_length,
        });
    }
    Ok(S19kBmuToc { build_id, entries })
}

/// FR-1.28 evidence contract: three variants, exact names, contiguous
/// blob tiling ending exactly at the container end.
pub fn admit_s19k_bmu_fr128_toc(toc: &S19kBmuToc) -> Result<(), &'static str> {
    if toc.build_id != S19K_BMU_FR128_BUILD_ID {
        return Err("FR-1.28 build id must stay f00dc230");
    }
    let want = [S19K_BMU_FR128_AML, S19K_BMU_FR128_ZYNQ, S19K_BMU_FR128_CV];
    if toc.entries.len() != want.len() {
        return Err("FR-1.28 must parse exactly three variant entries");
    }
    for (entry, (variant, offset, length, _sha)) in toc.entries.iter().zip(want) {
        if entry.variant != variant {
            return Err("FR-1.28 variant name mismatch");
        }
        if entry.blob_offset != offset || entry.blob_length != length {
            return Err("FR-1.28 variant offset/length mismatch");
        }
        if entry.file_name != "update.bmu" {
            return Err("FR-1.28 updater file name must stay update.bmu");
        }
        if entry.product != "Antminer S19k Pro" {
            return Err("FR-1.28 product must stay Antminer S19k Pro");
        }
    }
    let aml = &toc.entries[0];
    let zynq = &toc.entries[1];
    let cv = &toc.entries[2];
    if aml.blob_offset != S19K_BMU_FR128_BLOB_BASE {
        return Err("FR-1.28 AML blob must start at the blob base 0x4000");
    }
    if aml.blob_offset + aml.blob_length != zynq.blob_offset {
        return Err("FR-1.28 AML blob must end exactly where the zynq blob begins");
    }
    if zynq.blob_offset + zynq.blob_length != cv.blob_offset {
        return Err("FR-1.28 zynq blob must end exactly where the CV blob begins");
    }
    Ok(())
}

/// Each FR-1.28 variant blob keeps the legacy `26 01` lead, the 20251010
/// build date, and an RSA public-key PEM before the encrypted payload.
pub fn admit_s19k_bmu_variant_blob_shape(blob: &[u8]) -> Result<(), &'static str> {
    if blob.len() < 0x20 {
        return Err("variant blob too short for the 26 01 header");
    }
    if blob[0..2] != S19K_BMU_VARIANT_BLOB_LEAD {
        return Err("variant blob must still lead with 26 01");
    }
    if !blob
        .windows(S19K_BMU_FR128_BUILD_DATE.len())
        .any(|w| w == S19K_BMU_FR128_BUILD_DATE)
    {
        return Err("variant blob must carry the 20251010 build date");
    }
    if !blob
        .windows(S19K_BMU_VARIANT_PEM_MARKER.len())
        .any(|w| w == S19K_BMU_VARIANT_PEM_MARKER)
    {
        return Err("variant blob must embed the PUBLIC KEY PEM marker");
    }
    Ok(())
}

/// FR-1.28 is not the legacy single-image BMU: the TOC container is new
/// even though each variant payload keeps the `0x26 + PEM` family shape.
pub fn refuse_s19k_bmu_fr128_as_legacy_single_image() -> Result<(), &'static str> {
    Err(
        "FR-1.28 is a 3-variant TOC container (abababab); 26 01 + PEM lives \
         inside each variant blob, not at the container head",
    )
}

/// Flashing boundary pin: DCENT never writes a stock BMU to NAND.
pub fn refuse_s19k_bmu_nand_write() -> Result<(), &'static str> {
    Err("stock .bmu containers are RE evidence only; nandwrite of a BMU stays refused")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut out = vec![0u8; 0x8000];
        out[0..4].copy_from_slice(&S19K_BMU_TOC_MAGIC.to_le_bytes());
        out[8..12].copy_from_slice(&(0x24u32).to_le_bytes());
        out[12..16].copy_from_slice(&(S19K_BMU_FR128_ENTRY_COUNT as u32).to_le_bytes());
        out[16..20].copy_from_slice(&(S19K_BMU_TOC_ENTRY_STRIDE as u32).to_le_bytes());
        out[20..24].copy_from_slice(&S19K_BMU_FR128_BLOB_BASE.to_le_bytes());
        out[24..28].copy_from_slice(&S19K_BMU_FR128_BUILD_ID.to_le_bytes());
        let variants = [
            (0x1110_000au32, "AMLCtrl_BHB56XXX", 0x4000u32, 0x1000u32),
            (0x1111_000au32, "zynq7007_BHB56XXX", 0x5000u32, 0x1000u32),
            (0x110F_000au32, "CVCtrl_BHB56XXX", 0x6000u32, 0x1000u32),
        ];
        for (i, (tag, variant, offset, length)) in variants.iter().enumerate() {
            let (tag, variant, offset, length) = (*tag, (*variant).to_string(), *offset, *length);
            let base = 0x24 + i * S19K_BMU_TOC_ENTRY_STRIDE;
            out[base..base + 4].copy_from_slice(&tag.to_le_bytes());
            out[base + 0x04..base + 0x04 + 10].copy_from_slice(b"update.bmu");
            out[base + 0x44..base + 0x44 + variant.len()].copy_from_slice(variant.as_bytes());
            out[base + 0x64..base + 0x64 + 17].copy_from_slice(b"Antminer S19k Pro");
            out[base + 0xA4..base + 0xA8].copy_from_slice(&offset.to_le_bytes());
            out[base + 0xA8..base + 0xAC].copy_from_slice(&length.to_le_bytes());
            let blob = base_of_blob(offset);
            out[blob..blob + 2].copy_from_slice(&S19K_BMU_VARIANT_BLOB_LEAD);
            out[blob + 0x0D..blob + 0x15].copy_from_slice(S19K_BMU_FR128_BUILD_DATE);
            out[blob + 0x18..blob + 0x18 + S19K_BMU_VARIANT_PEM_MARKER.len()]
                .copy_from_slice(S19K_BMU_VARIANT_PEM_MARKER);
        }
        out
    }

    fn base_of_blob(offset: u32) -> usize {
        offset as usize
    }

    #[test]
    fn fr128_toc_parses_and_admits_with_contiguous_blobs() {
        let blob = fixture();
        let toc = parse_s19k_bmu_toc(&blob).expect("fixture TOC parse");
        assert_eq!(toc.build_id, S19K_BMU_FR128_BUILD_ID);
        assert_eq!(toc.entries.len(), 3);
        for entry in &toc.entries {
            assert!(admit_s19k_bmu_variant_blob_shape(
                &blob[entry.blob_offset as usize..(entry.blob_offset + entry.blob_length) as usize]
            )
            .is_ok());
        }
        // The fixture tiles blobs contiguously like FR-1.28, but the admit
        // pins the production offsets; check contiguity directly here.
        assert_eq!(
            toc.entries[0].blob_offset + toc.entries[0].blob_length,
            toc.entries[1].blob_offset
        );
        assert_eq!(
            toc.entries[1].blob_offset + toc.entries[1].blob_length,
            toc.entries[2].blob_offset
        );
        assert_eq!(toc.entries[0].blob_offset, S19K_BMU_FR128_BLOB_BASE);
    }

    #[test]
    fn fr128_evidence_constants_stay_pinned() {
        assert_eq!(S19K_BMU_FR128_AML.0, "AMLCtrl_BHB56XXX");
        assert_eq!(S19K_BMU_FR128_ZYNQ.0, "zynq7007_BHB56XXX");
        assert_eq!(S19K_BMU_FR128_CV.0, "CVCtrl_BHB56XXX");
        // Contiguity: AML end == zynq start, zynq end == CV start,
        // CV end == container size 0x2A89B34.
        assert_eq!(
            S19K_BMU_FR128_AML.1 + S19K_BMU_FR128_AML.2,
            S19K_BMU_FR128_ZYNQ.1
        );
        assert_eq!(
            S19K_BMU_FR128_ZYNQ.1 + S19K_BMU_FR128_ZYNQ.2,
            S19K_BMU_FR128_CV.1
        );
        assert_eq!(
            S19K_BMU_FR128_CV.1 + S19K_BMU_FR128_CV.2,
            0x2A89_B34u32,
            "FR-1.28 variants tile the whole 44,604,212-byte container"
        );
        assert_eq!(S19K_BMU_FR128_SHA256.len(), 64);
        assert!(refuse_s19k_bmu_fr128_as_legacy_single_image().is_err());
        assert!(refuse_s19k_bmu_nand_write().is_err());
    }

    #[test]
    fn bmu_toc_rejects_bad_magic_truncation_and_overrun() {
        let mut blob = fixture();
        blob[0] = 0xAC;
        assert!(parse_s19k_bmu_toc(&blob).is_err());
        let blob = fixture();
        assert!(parse_s19k_bmu_toc(&blob[..0x10]).is_err());
        let mut overrun = fixture();
        // Claim a blob length that extends past the container.
        let base = 0x24 + 2 * S19K_BMU_TOC_ENTRY_STRIDE;
        overrun[base + 0xA8..base + 0xAC].copy_from_slice(&0xFFFF_FFu32.to_le_bytes());
        assert!(parse_s19k_bmu_toc(&overrun).is_err());
        // Non-empty name required: wipe the first variant name.
        let mut anon = fixture();
        let b0 = 0x24;
        for i in 0..0x20 {
            anon[b0 + 0x44 + i] = 0;
        }
        assert!(parse_s19k_bmu_toc(&anon).is_err());
    }

    #[test]
    fn variant_blob_shape_requires_lead_date_and_pem() {
        let good = {
            let mut b = vec![0u8; 0x400];
            b[0..2].copy_from_slice(&S19K_BMU_VARIANT_BLOB_LEAD);
            b[0x0D..0x15].copy_from_slice(S19K_BMU_FR128_BUILD_DATE);
            b[0x18..0x18 + S19K_BMU_VARIANT_PEM_MARKER.len()]
                .copy_from_slice(S19K_BMU_VARIANT_PEM_MARKER);
            b
        };
        assert!(admit_s19k_bmu_variant_blob_shape(&good).is_ok());
        let mut bad_lead = good.clone();
        bad_lead[1] = 0x02;
        assert!(admit_s19k_bmu_variant_blob_shape(&bad_lead).is_err());
        let mut no_pem = good.clone();
        for byte in no_pem.iter_mut().skip(0x18).take(0x100) {
            *byte = b'x';
        }
        assert!(admit_s19k_bmu_variant_blob_shape(&no_pem).is_err());
    }
}
