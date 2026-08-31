//! FR-1.28 (251010) stock S19k Pro `.bmu` PAYLOAD-protection scheme
//! evidence (Gap-3 Track-2 desk RE, 2026-08-19).
//!
//! Companion to [`crate::s19k_stock_bmu_toc`], which parses the
//! `abababab` merge-container TOC. This module pins how each variant
//! blob's payload is protected and how far desk decryption reaches
//! with held assets. Read-only evidence: this module grants ZERO
//! install/flash authority (see the refuse functions at the bottom).
//!
//! ## Scheme (desk-proven 2026-08-19 against `FR-1.28(251010-S19k Pro).bmu`,
//! sha256 `46c6f682…`; every claim below was verified byte-exact on the
//! held file plus three controls — 2023-11-08 S19k Pro `update.bmu`, the
//! 2022-12 S19 Pro merge BMU, and the held FileParser decompilation)
//!
//! **Layer 1 — merge container (`abababab`):** 36-byte LE header
//! {magic, version=0, hdr_size=36, item_count=3, item_size=0xAC,
//! data_offset=0x4000, crc32@0x18, r0, r1}. The field the TOC module
//! documents as "build id" `0xF00D_C230` is actually the **CRC32 of the
//! whole file with bytes 0x18..0x1C zeroed** (verified: binascii-style
//! CRC32 of the 44,604,212-byte container = `0xF00D_C230`).
//!
//! **Layer 2 — each variant blob is a classic single-BMU (magic `0x26`,
//! fixed 2048-byte header):** miner-type hash @0x02 (u64 LE =
//! CityHash64/farmhash Fingerprint64 of the hardware string — all three
//! verified via `dcent_toolbox.bmu.parser.city_hash64`), content bitmap
//! @0x0B (u16 BE; the law FileParser enforces is popcount == component
//! count; observed conventions: `0x0200` = single-datafile AML-class
//! package — identical on the S19k Pro AML variant and every held
//! S21/S21-XP/S21-Pro/S21XP-Imm single BMU — `0xFE00` = 7-file zynq
//! package (also the `-x` full-package mask), `0xE000` = 3-file CV
//! package), build date @0x0D (8 ASCII,
//! `20251010`; zeroed in the 2023-11-08 build), PEM length @0x16 (u16 BE
//! = 451), embedded RSA-2048 `miner.pem` @0x18, `miner.pem.sig` @0x418,
//! component count @0x518 (== bitmap popcount), `{u8 type, u32 BE size}`
//! descriptors @0x51D stride 5, comment @0x550 (zeroed), components
//! concatenated from @0x800, then one 256-byte signature per component,
//! then a final 256-byte `bmu.sig`. Exact size law (all four files):
//! `blob_len == ((count + 9) << 8) + Σ size_i`.
//!
//! **Layer 3 — signatures only; the PEM is a VERIFY key:**
//! all signatures are RSA-2048 PKCS#1 v1.5 SHA-256 (held FileParser
//! `sub_10C70` calls `RSA_verify(672=NID_sha256, …, 256, key)`):
//! - `miner.pem.sig` @0x418 = Bitmain ROOT signature over SHA256(PEM).
//!   The root public key is NOT held (both held `/etc/bitmain.pub` roots
//!   fail). It is byte-identical between FR-1.28 AML and the 2023-11-08
//!   S19k Pro BMU because it signs the identical embedded AML PEM — NOT
//!   because it wraps a session key.
//! - Per-component 256-byte sig = embedded miner.pem signature over
//!   SHA256(component bytes). ALL 11 components across the three FR-1.28
//!   variants (plus the 2023-11-08 datafile) verify desk-side with the
//!   embedded per-variant PEM alone — no external key needed.
//! - `bmu.sig` (final 256 bytes) = embedded miner.pem signature over
//!   SHA256(check), where check = SHA256(header[0..0x800]) ||
//!   Σ SHA256(component_i) || Σ SHA256(component_sig_i), truncated to
//!   `(count << 6) + 32` bytes. ALL variants verify.
//!
//! **There is NO symmetric key wrap, NO AES/ECB/CBC layer, and NO payload
//! cipher at the BMU layer.** The only "encryption" in the container is
//! the AML variant's inner ANDROID! boot-image bodies (Layer 4).
//!
//! **Layer 4 — payload bytes:**
//! - zynq variant: PLAINTEXT (BOOT.bin = Zynq bootgen `fe ff ff ea`
//!   pattern, devicetree.dtb `d0 0d fe ed`, uImage `27 05 19 56`,
//!   minerfs/update images uImage-wrapped, crl + miner.btm = gzip) —
//!   fully unpackable and signature-verifiable desk-side TODAY.
//! - CV variant: PLAINTEXT (BOOT.bin = gzip `1f 8b`, the devicetree.dtb
//!   slot carries a `-----BEGIN PUBLIC KEY-----` PEM, the uImage slot
//!   carries a DTB) — unpackable today.
//! - AML variant: datafile = `ANDROID!` boot image (page 0x800,
//!   kernel 0x5C0800, ramdisk 0x750800, second 0x7800, cmdline
//!   `init=/sbin/init`); the kernel/ramdisk/second bodies are opaque
//!   high-entropy (≈7.997 bits/byte) with NO plaintext compression
//!   magic — the same "bodies after page 0 are encrypted" class as the
//!   2023-11-08 build. The inner Amlogic cipher remains UNBOUND and no
//!   held asset decrypts it.

/// Single-BMU magic byte (`0x26` = decimal 38, checked by FileParser
/// `validate_firmware_update` as `*buffer == 38`).
pub const S19K_BMU_SINGLE_MAGIC: u8 = 0x26;

/// Single-BMU fixed header length (files start at this offset).
pub const S19K_BMU_SINGLE_HEADER_LEN: usize = 0x800;

/// Offset of the u64-LE miner-type hash (CityHash64 of the hardware
/// string, e.g. `AMLCtrl_BHB56XXX`).
pub const S19K_BMU_MINER_TYPE_HASH_OFF: usize = 0x02;

/// Offset of the u16-BE content bitmap. FileParser enforces
/// popcount(bitmap) == component count; observed conventions:
/// `0x0200` (single-datafile AML-class), `0xFE00` (7-file zynq, also
/// the `-x` full-package mask), `0xE000` (3-file CV).
pub const S19K_BMU_CONTENT_BITMAP_OFF: usize = 0x0B;

/// Offset of the 8-byte ASCII build date (`20251010`).
pub const S19K_BMU_BUILD_DATE_OFF: usize = 0x0D;

/// Offset of the u16-BE embedded-PEM length (451 in every FR-1.28 blob).
pub const S19K_BMU_PEM_LEN_OFF: usize = 0x16;

/// Offset of the embedded RSA-2048 `miner.pem` (SPKI, 451 bytes).
pub const S19K_BMU_MINER_PEM_OFF: usize = 0x18;

/// Offset of the 256-byte `miner.pem.sig` (ROOT signature over the PEM).
pub const S19K_BMU_PEM_SIG_OFF: usize = 0x418;

/// Offset of the u8 component count (== content-bitmap popcount).
pub const S19K_BMU_FILE_COUNT_OFF: usize = 0x518;

/// Offset of the u32-BE exact-size field (zero in every observed file).
pub const S19K_BMU_EXACT_SIZE_OFF: usize = 0x519;

/// Offset of the first `{u8 type, u32 BE size}` descriptor.
pub const S19K_BMU_FILE_DESC_OFF: usize = 0x51D;

/// Descriptor stride: 1 byte type + 4 bytes BE size.
pub const S19K_BMU_FILE_DESC_STRIDE: usize = 5;

/// Offset of the 256-byte package comment (zeroed in FR-1.28).
pub const S19K_BMU_COMMENT_OFF: usize = 0x550;

/// Every signature blob in the container is exactly 256 bytes
/// (RSA-2048).
pub const S19K_BMU_SIG_LEN: usize = 256;

/// Signature scheme string pinned by the held FileParser decompilation
/// (`RSA_verify(672, digest, 32, sig, 256, key)`, i.e. NID_sha256 with
/// PKCS#1 v1.5).
pub const S19K_BMU_SIG_SCHEME: &str = "RSA-2048 PKCS#1 v1.5 SHA-256";

/// Length of the bmu.sig check chain prefix for `count` components:
/// SHA256(header) [32] + count file digests + count sig digests, i.e.
/// `(count << 6) + 32` bytes.
pub const fn s19k_bmu_check_chain_len(count: usize) -> usize {
    (count << 6) + 32
}

/// Canonical component names (FileParser `update_and_hash_firmware`
/// switch on firmware_type; same table as bmu.py `get_file_name`).
pub fn s19k_bmu_file_name(type_id: u8) -> Option<&'static str> {
    match type_id {
        0 => Some("BOOT.bin"),
        1 => Some("devicetree.dtb"),
        2 => Some("uImage"),
        3 => Some("minerfs.image.gz"),
        4 => Some("update.image.gz"),
        5 => Some("crl.tar.gz"),
        6 => Some("miner.btm.tar.gz"),
        7 => Some("reserve"),
        9 => Some("datafile"),
        _ => None,
    }
}

/// FR-1.28 merge-container CRC32: field @0x18 equals the CRC32 of the
/// whole 44,604,212-byte file with bytes 0x18..0x1C zeroed (verified
/// desk-side 2026-08-19). This is the value the TOC module documents as
/// `S19K_BMU_FR128_BUILD_ID`.
pub const S19K_BMU_FR128_MERGE_CRC32: u32 = 0xF00D_C230;

/// Per-variant payload evidence table (all values read from the held
/// FR-1.28 file; PEM/sig sha256 pins allow future re-verification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kBmuVariantEvidence {
    /// Merge-TOC hardware string (also the CityHash64 preimage).
    pub hardware: &'static str,
    /// u64-LE @0x02 = CityHash64(hardware) (verified via the toolbox
    /// `city_hash64` oracle, which matches farmhash Fingerprint64).
    pub miner_type_hash: u64,
    /// u16-BE @0x0B content bitmap.
    pub content_bitmap: u16,
    /// `{type, BE size}` component table in file order.
    pub files: &'static [(u8, u32)],
    /// sha256 of the embedded 451-byte miner.pem.
    pub pem_sha256: &'static str,
    /// sha256 of the 256-byte miner.pem.sig @0x418.
    pub pem_sig_sha256: &'static str,
}

/// FR-1.28 AML variant evidence. The PEM and its root signature are
/// byte-identical to the 2023-11-08 S19k Pro `update.bmu` (same
/// `AMLCtrl_BHB56XXX` packaging key lineage).
pub const S19K_BMU_FR128_AML_EVIDENCE: S19kBmuVariantEvidence = S19kBmuVariantEvidence {
    hardware: "AMLCtrl_BHB56XXX",
    miner_type_hash: 0xB090_9B8B_D8F3_6BFB,
    content_bitmap: 0x0200,
    files: &[(9, 0xD19200)],
    pem_sha256: "f03c6e8345cb3cfec6792b3ef545cc2e2166661492683c20e8f0166aba8c8ad0",
    pem_sig_sha256: "cf4529f7a4e66f84f68fc723006b71baab796cb76092b1c5b58246b6ea0d5b77",
};

/// FR-1.28 zynq variant evidence (7 plaintext boot-chain components).
pub const S19K_BMU_FR128_ZYNQ_EVIDENCE: S19kBmuVariantEvidence = S19kBmuVariantEvidence {
    hardware: "zynq7007_BHB56XXX",
    miner_type_hash: 0x059D_00A7_D35B_EB11,
    content_bitmap: 0xFE00,
    files: &[
        (0, 0x2A8CC0),
        (1, 0x1F4E),
        (2, 0x3DE8E8),
        (3, 0x6AB06B),
        (4, 0x414CB2),
        (5, 0x228),
        (6, 0x3ED),
    ],
    pem_sha256: "2dab0504d7c2f083ca940332534d43e1d0f40a582792554cf40b4bc1be2f6103",
    pem_sig_sha256: "7b4df8873c09a219235a2cc2cf03452bfc3e0ccd7a99735219d66f507eb689a5",
};

/// FR-1.28 CV variant evidence (3 plaintext components).
pub const S19K_BMU_FR128_CV_EVIDENCE: S19kBmuVariantEvidence = S19kBmuVariantEvidence {
    hardware: "CVCtrl_BHB56XXX",
    miner_type_hash: 0x0429_C2DC_209A_8D70,
    content_bitmap: 0xE000,
    files: &[(0, 0x7AC929), (1, 0xB75), (2, 0x47366E)],
    pem_sha256: "5be76d487beb73c647983f61204a70948b6da37a79cf23e13b9039e5133c92fc",
    pem_sig_sha256: "b857aa012ddc690ab42dffd855902c0d38f441bca3d6368254945cc2497f9230",
};

/// FR-1.28 AML datafile sha256 (`ANDROID!` boot image).
pub const S19K_BMU_FR128_AML_DATAFILE_SHA256: &str =
    "dd644a5ab0fc78d218828c9e44a257517ca6eaead2fd690fd87ac2633286d38a";

/// 2023-11-08 S19k Pro `update.bmu` datafile sha256 (AML lineage
/// control; same PEM + same miner.pem.sig, different payload).
pub const S19K_BMU_20231108_DATAFILE_SHA256: &str =
    "67987a104328adc951468573c90cecab3945ebe55885a49e5be6d1c9e82f89b1";

/// FR-1.28 AML ANDROID! boot-image header pins (LE u32 @8..36).
pub const S19K_BMU_FR128_AML_ANDROID_KERNEL_SIZE: u32 = 0x5C0800;
/// FR-1.28 AML ramdisk size (grew from 0x66A000 in the 2023-11-08
/// build; the kernel size is unchanged).
pub const S19K_BMU_FR128_AML_ANDROID_RAMDISK_SIZE: u32 = 0x750800;
/// 2023-11-08 AML ramdisk size (ledger control).
pub const S19K_BMU_20231108_AML_ANDROID_RAMDISK_SIZE: u32 = 0x66A000;
/// Second-stage size (identical in both builds).
pub const S19K_BMU_AML_ANDROID_SECOND_SIZE: u32 = 0x7800;
/// ANDROID! page size.
pub const S19K_BMU_AML_ANDROID_PAGE: u32 = 0x800;
/// ANDROID! boot-image magic.
pub const S19K_BMU_AML_ANDROID_MAGIC: &[u8] = b"ANDROID!";

/// First 16 bytes of the FR-1.28 AML kernel body (page 1). Pinned to
/// prove the body carries no plaintext compression/boot magic: it is
/// opaque ciphertext-class bytes (measured entropy ≈7.997 bits/byte).
pub const S19K_BMU_FR128_AML_KERNEL_BODY_HEAD: [u8; 16] = [
    0x01, 0xAB, 0x3B, 0xDF, 0xDC, 0xF1, 0x4A, 0x05, 0xBE, 0x32, 0x59, 0x35, 0xDA, 0xFF, 0xF0, 0xAB,
];

/// First 16 bytes of the FR-1.28 AML ramdisk body (same opacity class).
pub const S19K_BMU_FR128_AML_RAMDISK_BODY_HEAD: [u8; 16] = [
    0x56, 0xEF, 0xB9, 0x89, 0x58, 0x60, 0xE4, 0x6B, 0x6D, 0x90, 0x66, 0x80, 0xE1, 0x85, 0x79, 0x37,
];

/// Known plaintext magics the AML bodies must NOT start with (gzip,
/// legacy uImage, FDT, ARM64 Image, LZMA, xz, lz4). If a future build's
/// body matches one of these, the "encrypted bodies" claim is stale.
pub const S19K_BMU_PLAINTEXT_MAGICS: [&[u8]; 7] = [
    &[0x1F, 0x8B],                   // gzip
    &[0x27, 0x05, 0x19, 0x56],       // uImage
    &[0xD0, 0x0D, 0xFE, 0xED],       // FDT/DTB
    &[0x41, 0x52, 0x4D, 0x64],       // ARM64 Image ("ARM\x64")
    &[0x5D, 0x00, 0x00],             // LZMA alone
    &[0xFD, 0x37, 0x7A, 0x58, 0x5A], // xz
    &[0x04, 0x22, 0x4D, 0x18],       // lz4 frame
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kBmuSingleHeader {
    pub version: u8,
    pub miner_type_hash: u64,
    pub content_bitmap: u16,
    pub build_date: [u8; 8],
    pub pem_len: u16,
    pub pem_marker_present: bool,
    pub file_count: u8,
    pub files: Vec<(u8, u32)>,
}

fn u16_be(blob: &[u8], at: usize) -> Result<u16, &'static str> {
    let b = blob
        .get(at..at + 2)
        .ok_or("bmu single header truncated before u16 field")?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn u32_be(blob: &[u8], at: usize) -> Result<u32, &'static str> {
    let b = blob
        .get(at..at + 4)
        .ok_or("bmu single header truncated before u32 field")?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Parse and structurally validate a variant single-BMU blob: magic,
/// header length, bitmap/count agreement, descriptor window, and the
/// exact size law `len == ((count + 9) << 8) + Σ sizes` (which also
/// proves the per-file sigs + final bmu.sig tile the tail exactly:
/// `0x800 + Σ sizes + count*256 + 256 == len`).
pub fn parse_s19k_bmu_single_header(blob: &[u8]) -> Result<S19kBmuSingleHeader, &'static str> {
    if blob.len() < S19K_BMU_SINGLE_HEADER_LEN {
        return Err("bmu single blob shorter than the fixed 2048-byte header");
    }
    if blob[0] != S19K_BMU_SINGLE_MAGIC {
        return Err("bmu single blob magic is not 26");
    }
    let version = blob[1];
    let miner_type_hash = u64::from_le_bytes(
        blob[S19K_BMU_MINER_TYPE_HASH_OFF..0x0A]
            .try_into()
            .map_err(|_| "bmu miner-type hash window")?,
    );
    let content_bitmap = u16_be(blob, S19K_BMU_CONTENT_BITMAP_OFF)?;
    let build_date: [u8; 8] = blob[S19K_BMU_BUILD_DATE_OFF..0x15]
        .try_into()
        .map_err(|_| "bmu build-date window")?;
    let pem_len = u16_be(blob, S19K_BMU_PEM_LEN_OFF)?;
    if pem_len as usize + S19K_BMU_MINER_PEM_OFF > S19K_BMU_PEM_SIG_OFF {
        return Err("bmu embedded PEM overlaps the PEM signature window");
    }
    let pem_marker_present = blob
        [S19K_BMU_MINER_PEM_OFF..S19K_BMU_MINER_PEM_OFF + pem_len as usize]
        .windows(26)
        .any(|w| w == b"-----BEGIN PUBLIC KEY-----");
    let file_count = blob[S19K_BMU_FILE_COUNT_OFF];
    if file_count as u32 != content_bitmap.count_ones() {
        return Err("bmu component count does not equal the content-bitmap popcount");
    }
    let mut files = Vec::with_capacity(file_count as usize);
    let mut total = ((file_count as u32 + 9) << 8) as u64;
    for i in 0..file_count as usize {
        let base = S19K_BMU_FILE_DESC_OFF + i * S19K_BMU_FILE_DESC_STRIDE;
        let type_id = *blob.get(base).ok_or("bmu descriptor window overrun")?;
        if s19k_bmu_file_name(type_id).is_none() {
            return Err("bmu descriptor carries an unknown component type");
        }
        let size = u32_be(blob, base + 1)?;
        total += u64::from(size);
        files.push((type_id, size));
    }
    if total != blob.len() as u64 {
        return Err("bmu single blob violates the (count+9)<<8 + sum(size) size law");
    }
    Ok(S19kBmuSingleHeader {
        version,
        miner_type_hash,
        content_bitmap,
        build_date,
        pem_len,
        pem_marker_present,
        file_count,
        files,
    })
}

/// Admit a parsed FR-1.28 variant header against its pinned evidence
/// table (miner-type hash, bitmap, component table, 451-byte PEM).
pub fn admit_s19k_bmu_variant_header(
    header: &S19kBmuSingleHeader,
    evidence: &S19kBmuVariantEvidence,
) -> Result<(), &'static str> {
    if header.miner_type_hash != evidence.miner_type_hash {
        return Err("variant miner-type hash does not match the pinned evidence");
    }
    if header.content_bitmap != evidence.content_bitmap {
        return Err("variant content bitmap does not match the pinned evidence");
    }
    if header.files != evidence.files {
        return Err("variant component table does not match the pinned evidence");
    }
    if header.pem_len != 451 || !header.pem_marker_present {
        return Err("variant must embed the 451-byte RSA public-key PEM");
    }
    Ok(())
}

/// The BMU layer carries signatures, not a wrapped session key: the
/// embedded PEM is used only by `RSA_verify`. Any claim that the
/// `0x418` blob (or any 256-byte trailer) is an RSA-OAEP/PKCS1-wrapped
/// AES key is refused.
pub fn refuse_s19k_bmu_symmetric_key_wrap_claim() -> Result<(), &'static str> {
    Err(
        "the S19k Pro .bmu layer is signature-only (RSA-2048 PKCS#1v15 \
         SHA-256); there is no symmetric key wrap to attack or reproduce",
    )
}

/// The AML variant's inner ANDROID! kernel/ramdisk/second bodies stay
/// opaque with held assets: no held S19k AML decryptor exists, the
/// inner cipher is unbound, the S21-style AMLSECU! parser rejects the
/// S19k page-0 stamp, and the packaging ROOT key (needed only to
/// authenticate miner.pem, not to decrypt) is not held either.
pub fn refuse_s19k_bmu_aml_body_decrypt_with_held_assets() -> Result<(), &'static str> {
    Err(
        "AML inner boot-image bodies are high-entropy with no plaintext \
         magic; the inner cipher is unbound and no held asset decrypts it",
    )
}

/// This module is read-only RE evidence. The canonical NAND-write
/// refusal lives in `s19k_stock_bmu_toc::refuse_s19k_bmu_nand_write`
/// and stays authoritative; this mirror exists so the payload module
/// cannot be cited as install authority on its own.
pub fn refuse_s19k_bmu_payload_module_install_authority() -> Result<(), &'static str> {
    Err(
        "payload evidence module grants zero install/flash authority; \
         CLEAR_FOR_FLASH stays false and stock BMU nandwrite stays refused",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s19k_stock_bmu_toc::{
        admit_s19k_bmu_variant_blob_shape, parse_s19k_bmu_toc, S19K_BMU_FR128_AML,
        S19K_BMU_FR128_CV, S19K_BMU_FR128_ZYNQ, S19K_BMU_VARIANT_PEM_MARKER,
    };

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }

    /// Synthetic single-BMU fixture (two components) built to the exact
    /// on-disk law, mirroring how the FR-1.28 blobs tile.
    fn single_fixture(files: &[(u8, u32)]) -> Vec<u8> {
        let count = files.len() as u8;
        let mut out = vec![0u8; S19K_BMU_SINGLE_HEADER_LEN];
        out[0] = S19K_BMU_SINGLE_MAGIC;
        out[1] = 0x01;
        out[S19K_BMU_MINER_TYPE_HASH_OFF..0x0A]
            .copy_from_slice(&0xB090_9B8B_D8F3_6BFBu64.to_le_bytes());
        // bitmap: arbitrary distinct bits — only popcount == count is law.
        let bitmap: u16 = files.iter().fold(0, |acc, &(t, _)| acc | (1 << (t % 16)));
        out[S19K_BMU_CONTENT_BITMAP_OFF..0x0D].copy_from_slice(&bitmap.to_be_bytes());
        out[S19K_BMU_BUILD_DATE_OFF..0x15].copy_from_slice(b"20251010");
        out[S19K_BMU_PEM_LEN_OFF..0x18].copy_from_slice(&451u16.to_be_bytes());
        out[S19K_BMU_MINER_PEM_OFF..S19K_BMU_MINER_PEM_OFF + S19K_BMU_VARIANT_PEM_MARKER.len()]
            .copy_from_slice(S19K_BMU_VARIANT_PEM_MARKER);
        out[S19K_BMU_FILE_COUNT_OFF] = count;
        for (i, &(t, sz)) in files.iter().enumerate() {
            let base = S19K_BMU_FILE_DESC_OFF + i * S19K_BMU_FILE_DESC_STRIDE;
            out[base] = t;
            out[base + 1..base + 5].copy_from_slice(&sz.to_be_bytes());
            out.extend(std::iter::repeat_n(0xA5, sz as usize));
        }
        for _ in 0..count {
            out.extend(std::iter::repeat_n(0x5A, S19K_BMU_SIG_LEN));
        }
        out.extend(std::iter::repeat_n(0xC3, S19K_BMU_SIG_LEN));
        out
    }

    #[test]
    fn single_header_parses_and_admits_fixture() {
        let files = [(0u8, 0x100u32), (2, 0x80)];
        let blob = single_fixture(&files);
        let header = parse_s19k_bmu_single_header(&blob).expect("fixture parse");
        assert_eq!(header.version, 1);
        assert_eq!(header.miner_type_hash, 0xB090_9B8B_D8F3_6BFB);
        assert_eq!(header.content_bitmap, 0x0005);
        assert_eq!(&header.build_date, b"20251010");
        assert_eq!(header.pem_len, 451);
        assert!(header.pem_marker_present);
        assert_eq!(header.file_count, 2);
        assert_eq!(header.files, vec![(0, 0x100), (2, 0x80)]);
        // Tail tiling: header + data + count*256 sigs + final 256.
        let data_len: usize = files.iter().map(|&(_, s)| s as usize).sum();
        assert_eq!(
            blob.len(),
            S19K_BMU_SINGLE_HEADER_LEN + data_len + 3 * S19K_BMU_SIG_LEN
        );
    }

    #[test]
    fn single_header_rejects_bad_magic_count_and_size_law() {
        let files = [(0u8, 0x100u32)];
        let mut bad_magic = single_fixture(&files);
        bad_magic[0] = 0x27;
        assert!(parse_s19k_bmu_single_header(&bad_magic).is_err());
        let mut bad_count = single_fixture(&files);
        bad_count[S19K_BMU_FILE_COUNT_OFF] = 2;
        assert!(parse_s19k_bmu_single_header(&bad_count).is_err());
        let mut bad_size = single_fixture(&files);
        // Size BE bytes at +1..+5 are 00 00 01 00 (0x100); double the 0x01
        // digit to 0x02 so the size law no longer reproduces the blob len.
        assert_eq!(bad_size[S19K_BMU_FILE_DESC_OFF + 3], 0x01);
        bad_size[S19K_BMU_FILE_DESC_OFF + 3] = 0x02;
        assert!(parse_s19k_bmu_single_header(&bad_size).is_err());
        let mut bad_type = single_fixture(&files);
        bad_type[S19K_BMU_FILE_DESC_OFF] = 8; // unknown component type
        assert!(parse_s19k_bmu_single_header(&bad_type).is_err());
        let truncated = &single_fixture(&files)[..0x400];
        assert!(parse_s19k_bmu_single_header(truncated).is_err());
    }

    #[test]
    fn fr128_evidence_tables_stay_self_consistent() {
        let tables = [
            (
                &S19K_BMU_FR128_AML_EVIDENCE,
                S19K_BMU_FR128_AML.1,
                S19K_BMU_FR128_AML.2,
            ),
            (
                &S19K_BMU_FR128_ZYNQ_EVIDENCE,
                S19K_BMU_FR128_ZYNQ.1,
                S19K_BMU_FR128_ZYNQ.2,
            ),
            (
                &S19K_BMU_FR128_CV_EVIDENCE,
                S19K_BMU_FR128_CV.1,
                S19K_BMU_FR128_CV.2,
            ),
        ];
        for (evidence, blob_len_offset_unused, blob_len) in tables {
            let _ = blob_len_offset_unused;
            // Hardware string is the merge-TOC variant name.
            // (Direct cross-check against the TOC tuples happens below.)
            assert_eq!(
                evidence.content_bitmap.count_ones() as usize,
                evidence.files.len(),
                "bitmap popcount must equal the component count"
            );
            let sum: u64 = evidence
                .files
                .iter()
                .map(|&(_, s)| u64::from(s))
                .sum::<u64>()
                + ((evidence.files.len() as u64 + 9) << 8);
            assert_eq!(
                sum,
                u64::from(blob_len),
                "size law must reproduce the merge-TOC blob length for {}",
                evidence.hardware
            );
            assert_eq!(evidence.pem_sha256.len(), 64);
            assert_eq!(evidence.pem_sig_sha256.len(), 64);
        }
        // Cross-module lineage: hardware names match the TOC tuples.
        assert_eq!(S19K_BMU_FR128_AML_EVIDENCE.hardware, S19K_BMU_FR128_AML.0);
        assert_eq!(S19K_BMU_FR128_ZYNQ_EVIDENCE.hardware, S19K_BMU_FR128_ZYNQ.0);
        assert_eq!(S19K_BMU_FR128_CV_EVIDENCE.hardware, S19K_BMU_FR128_CV.0);
    }

    #[test]
    fn fr128_variant_evidence_admits_synthetic_headers() {
        for evidence in [
            &S19K_BMU_FR128_AML_EVIDENCE,
            &S19K_BMU_FR128_ZYNQ_EVIDENCE,
            &S19K_BMU_FR128_CV_EVIDENCE,
        ] {
            let blob = single_fixture(evidence.files);
            // Force the fixture's bitmap/count to the evidence values.
            let mut blob = blob;
            blob[S19K_BMU_CONTENT_BITMAP_OFF..0x0D]
                .copy_from_slice(&evidence.content_bitmap.to_be_bytes());
            blob[S19K_BMU_FILE_COUNT_OFF] = evidence.files.len() as u8;
            blob[S19K_BMU_MINER_TYPE_HASH_OFF..0x0A]
                .copy_from_slice(&evidence.miner_type_hash.to_le_bytes());
            let header = parse_s19k_bmu_single_header(&blob).expect("evidence-shaped parse");
            assert!(admit_s19k_bmu_variant_header(&header, evidence).is_ok());
            // The fixture keeps the 26 01 lead so the TOC shape check
            // (cross-module consistency) also admits it.
            assert!(admit_s19k_bmu_variant_blob_shape(&blob).is_ok());
        }
    }

    #[test]
    fn aml_lineage_pins_the_shared_packaging_key() {
        // Same 451-byte PEM and same root signature across the
        // 2023-11-08 S19k Pro BMU and FR-1.28 AML (byte-identical,
        // pinned by equal sha256). Different payload digests prove the
        // 0x418 blob is a signature over the constant PEM, not a
        // per-payload wrapped key.
        assert_eq!(
            S19K_BMU_FR128_AML_EVIDENCE.pem_sha256,
            "f03c6e8345cb3cfec6792b3ef545cc2e2166661492683c20e8f0166aba8c8ad0"
        );
        assert_eq!(
            S19K_BMU_FR128_AML_EVIDENCE.pem_sig_sha256,
            "cf4529f7a4e66f84f68fc723006b71baab796cb76092b1c5b58246b6ea0d5b77"
        );
        assert_ne!(
            S19K_BMU_FR128_AML_DATAFILE_SHA256,
            S19K_BMU_20231108_DATAFILE_SHA256
        );
        // Android header lineage: kernel size unchanged, ramdisk grew.
        assert_eq!(
            S19K_BMU_FR128_AML_ANDROID_KERNEL_SIZE, 0x5C0800,
            "same kernel body size as the 2023-11-08 build"
        );
        assert_ne!(
            S19K_BMU_FR128_AML_ANDROID_RAMDISK_SIZE,
            S19K_BMU_20231108_AML_ANDROID_RAMDISK_SIZE
        );
        assert_eq!(
            S19K_BMU_AML_ANDROID_PAGE, 0x800,
            "ANDROID page size stays 0x800"
        );
        assert_eq!(S19K_BMU_AML_ANDROID_MAGIC, b"ANDROID!");
    }

    #[test]
    fn aml_bodies_carry_no_plaintext_magic() {
        for head in [
            &S19K_BMU_FR128_AML_KERNEL_BODY_HEAD,
            &S19K_BMU_FR128_AML_RAMDISK_BODY_HEAD,
        ] {
            for magic in S19K_BMU_PLAINTEXT_MAGICS {
                assert_ne!(
                    &head[..magic.len().min(head.len())],
                    magic,
                    "AML body unexpectedly starts with a plaintext magic"
                );
            }
        }
    }

    #[test]
    fn check_chain_length_layout_matches_fileparser() {
        // FileParser: SHA256_Update(ctx, sha256_result_2,
        // (content_flags_set_bit_count << 6) + 32).
        assert_eq!(s19k_bmu_check_chain_len(1), 96);
        assert_eq!(s19k_bmu_check_chain_len(3), 224);
        assert_eq!(s19k_bmu_check_chain_len(7), 480);
    }

    #[test]
    fn merge_crc32_semantics_and_vector() {
        // Standard reflected CRC-32 (the merge-container field
        // algorithm, verified against the FR-1.28 file value).
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(S19K_BMU_FR128_MERGE_CRC32, 0xF00D_C230);
    }

    #[test]
    fn refuses_stay_refused_and_toc_nand_refusal_untouched() {
        assert!(refuse_s19k_bmu_symmetric_key_wrap_claim().is_err());
        assert!(refuse_s19k_bmu_aml_body_decrypt_with_held_assets().is_err());
        assert!(refuse_s19k_bmu_payload_module_install_authority().is_err());
        // The canonical NAND-write refusal stays authoritative.
        assert!(crate::s19k_stock_bmu_toc::refuse_s19k_bmu_nand_write().is_err());
    }

    #[test]
    fn fr128_container_evidence_shape_cross_checks() {
        // The merge container itself keeps parsing under the TOC module
        // (structure only; no container bytes are embedded here, so we
        // assert the cross-referenced pins instead).
        assert_eq!(S19K_BMU_SIG_SCHEME, "RSA-2048 PKCS#1 v1.5 SHA-256");
        assert_eq!(S19K_BMU_SIG_LEN, 256);
        // TOC entry-count law still binds three variants.
        let _ = parse_s19k_bmu_toc;
        assert_eq!(crate::s19k_stock_bmu_toc::S19K_BMU_FR128_ENTRY_COUNT, 3);
    }
}
