// SPDX-License-Identifier: GPL-3.0-or-later
//
// AUP firmware container parser/builder.
//
// Format reference (canonical Kaitai schema):
//    (Apache-2.0)
//    §3.1-3.2
//
// `fmt_ver` DISPATCH — the header layout depends on the version field @ 0x10:
//   v0 (92 B):  payload_len @0x14, firmware_ver[64] @0x18, payload_crc @0x58.
//   v1 (224 B): header_len @0x14, hw_list_str[128] @0x18, payload_len @0x98,
//               firmware_ver[64] @0x9C, payload_crc @0xDC (comma-separated hw list).
//   v2 (var):   the K210 industrial layout documented below (hw_list/sw_list arrays).
// v1 shifts every field after the 128-byte hw_list_str, so each version is parsed
// with its OWN offset set (`AupHeader::parse` dispatches on `fmt_ver`). Reading a real
// v0/v1 package at the v2 absolute offsets silently mis-parses it — that was the bug.
//
// Wire layout for fmt_ver = 0x02 (industrial K210 firmware corpus, all 8 ZIPs),
// per AVALON_INDUSTRIAL_FW_RE.md §3.1 (lines 71-86), all integers little-endian:
//
//   offset  size   field             notes
//   0x00    16     magic             "AUP format" + 6 NUL bytes
//   0x10    4      fmt_ver           0x00, 0x01, or 0x02 (= 2 for this set)
//   0x14    4      payload_len       length of the encrypted payload (LE u32)
//   0x18    64     firmware_ver      "<date>_<mm-sha>_<product-sha>", NUL-padded
//   0x58    4      payload_crc32     zlib.crc32 over the encrypted payload
//   0x5c    4      hw_list_count     usually 1
//   0x60    4      sw_list_count     2 (release + OOW = "Out-Of-Warranty")
//   0x64    32*N   hw_list           fixed-32-byte HW-target strings
//   ...     32*M   sw_list           fixed-32-byte SW-target strings
//   ...     4      header_crc32      zlib.crc32 over bytes [0 .. end_of_sw_list]
//   ...     *      body              encrypted K210 boot image (see below)
//
// The header size is VARIABLE: `0x64 + 32*hw_list_count + 32*sw_list_count + 4`
// (§3.1 line 98 marks the fmt_ver 2 header size as "variable"). For all 8 shipped
// industrial firmwares (1 hw + 2 sw entries) it is exactly **200 bytes**
// (§3.1 line 86: `0x64 + 32 + 64 + 4 = 200`), so for this corpus
// `AUP_BODY_OFFSET == AUP_HEADER_SIZE == 200`. A future multi-entry firmware MUST
// compute the body offset from the parsed list counts (see `aup_header_size`).
//
// Industrial K210 body (after the header), per §3.2 lines 104-112:
//   - byte 0          = aes_enable (0x00 = plaintext, 0x01 = AES-CBC)
//   - bytes 1..5      = app_size (inner_size) LE u32
//   - bytes 5..N+5    = ciphertext or plaintext (N = app_size)
//   - bytes N+5..N+37 = trailing SHA-256 over (aes_enable || size_LE || app_bin)
//   §3.2 line 112: `payload_len == 5 + app_size + 32` (8/8 exact match).
//
// All 8 industrial firmwares share the same K210 OTP-fused AES key + IV (proven
// by byte-identical first 224 B of ciphertext across the corpus). Authenticity
// gates entirely on the OTP fuses — NO RSA, NO asymmetric signature.
// §1-3.
//
//: this is a clean translation from
// the Apache-2.0 fms-core schema, not the BUSL-1.1 Avalon_mm source.

pub const AUP_HEADER_SIZE: usize = 200;
pub const AUP_MAGIC: &[u8; 16] = b"AUP format\x00\x00\x00\x00\x00\x00";
pub const AUP_FMT_VER_OFFSET: usize = 0x10;
pub const AUP_BODY_LEN_OFFSET: usize = 0x14;

/// Fixed header size for `fmt_ver == 0` (§ AUP_FORMAT: `16 + 4 + 4 + 64 + 4`).
pub const AUP_V0_HEADER_SIZE: usize = 92;
/// Fixed header size for `fmt_ver == 1` (`16 + 4 + 4 + 128 + 4 + 64 + 4`).
pub const AUP_V1_HEADER_SIZE: usize = 224;
/// Smallest possible valid AUP header of ANY version (v0 = 92 bytes). Used as the
/// pre-magic length floor so a truncated buffer reports `ShortBuffer` (not `BadMagic`)
/// and so v0/v1/v2 can each apply their own, larger, per-version length check after
/// the `fmt_ver` dispatch.
pub const AUP_MIN_HEADER_SIZE: usize = AUP_V0_HEADER_SIZE;

// ---- v1-specific absolute field offsets (all little-endian) ----
// v1 shifts every field after the 128-byte hw_list_str vs v0/v2, so v1 needs its
// own offset set — reading v1 at v2 offsets is exactly defect #1.
/// v1 `header_len` u32 (≈224) @ 0x14.
pub const AUP_V1_HEADER_LEN_OFFSET: usize = 0x14;
/// v1 `hw_list_str` (128-byte comma-separated, NUL-padded) @ 0x18.
pub const AUP_V1_HW_LIST_STR_OFFSET: usize = 0x18;
/// Width of the v1 `hw_list_str` field.
pub const AUP_V1_HW_LIST_STR_SIZE: usize = 128;
/// v1 `payload_len` u32 @ 0x98 (= 0x18 + 128).
pub const AUP_V1_PAYLOAD_LEN_OFFSET: usize = 0x98;
/// v1 `firmware_ver[64]` @ 0x9C.
pub const AUP_V1_FIRMWARE_VER_OFFSET: usize = 0x9C;
/// v1 `payload_crc` u32 @ 0xDC.
pub const AUP_V1_PAYLOAD_CRC32_OFFSET: usize = 0xDC;

/// Offset of the 64-byte `firmware_ver` ASCII string (§3.1 line 76: `0x18 64 firmware_ver`).
pub const AUP_FIRMWARE_VER_OFFSET: usize = 0x18;
/// Width of the `firmware_ver` field per the canonical layout (64 bytes, NUL-padded).
pub const AUP_FIRMWARE_VER_SIZE: usize = 64;

/// Back-compat alias: the historical 8-byte "tag" was just the first 8 bytes of
/// `firmware_ver` (offset unchanged). Kept so `tag_str()` callers keep compiling.
/// Prefer `AUP_FIRMWARE_VER_OFFSET` / `firmware_ver_str()`.
pub const AUP_TAG_OFFSET: usize = AUP_FIRMWARE_VER_OFFSET;
pub const AUP_TAG_SIZE: usize = 8;

/// Offset of `payload_crc32` (zlib.crc32 over the encrypted payload). §3.1 line 77: `0x58`.
pub const AUP_PAYLOAD_CRC32_OFFSET: usize = 0x58;
/// Offset of `hw_list_count` (u32 LE). §3.1 line 78: `0x5c`.
pub const AUP_HW_LIST_COUNT_OFFSET: usize = 0x5c;
/// Offset of `sw_list_count` (u32 LE). §3.1 line 79: `0x60`.
pub const AUP_SW_LIST_COUNT_OFFSET: usize = 0x60;
/// Offset where the hw_list / sw_list 32-byte entries begin. §3.1 line 80: `0x64`.
pub const AUP_LIST_BASE_OFFSET: usize = 0x64;

/// Compute the TRUE AUP v2 header size for a firmware with the given list counts.
///
/// Per AVALON_INDUSTRIAL_FW_RE.md §3.1 (lines 80-86):
/// `0x64 + 32*hw_list_count + 32*sw_list_count + 4`.
/// Returns 200 for the shipped 1-hw/2-sw corpus (== `AUP_HEADER_SIZE`).
pub const fn aup_header_size(hw_list_count: usize, sw_list_count: usize) -> usize {
    AUP_LIST_BASE_OFFSET + 32 * hw_list_count + 32 * sw_list_count + 4
}

/// Start of the body (encrypted K210 boot image), immediately after the header.
///
/// For the shipped industrial corpus (1 hw_list entry + 2 sw_list entries) the
/// header is **exactly 200 bytes** (AVALON_INDUSTRIAL_FW_RE.md §3.1 line 86:
/// `0x64 + 32*1 + 32*2 + 4 = 200`), so the body begins at 0xC8 == 200.
///
/// ⚠️ The TRUE header size is VARIABLE (§3.1 line 98 marks fmt_ver 2 "variable"):
/// `0x64 + 32*hw_list_count + 32*sw_list_count + 4` (see `aup_header_size`).
/// 200/0xC8 is the *corpus-specific* value for 1-hw/2-sw firmware. A future
/// multi-entry firmware needs the computed offset, not this constant.
///
/// (Was `0xBC` / 188 — a real framing-corruption bug: slicing the body at 188 fed
/// the last 12 header bytes into `AupBody::parse` as aes_enable + inner_size.)
pub const AUP_BODY_OFFSET: usize = AUP_HEADER_SIZE;

// Compile-time guarantees: the body begins exactly at the end of the header, and
// the corpus list-count formula reproduces the 200-byte header size.
const _: () = assert!(AUP_BODY_OFFSET == AUP_HEADER_SIZE);
const _: () = assert!(AUP_BODY_OFFSET == aup_header_size(1, 2));

#[derive(Debug, thiserror::Error)]
pub enum AupError {
    #[error("buffer too small: AUP requires at least {AUP_MIN_HEADER_SIZE} bytes (v0), got {0}")]
    ShortBuffer(usize),

    #[error("magic mismatch: expected 'AUP format\\0\\0\\0\\0\\0\\0' at offset 0, got {0:?}")]
    BadMagic([u8; 16]),

    #[error("unsupported fmt_ver {0} (supported: 0..=2)")]
    UnsupportedFmtVer(u8),

    #[error("body_len {0} exceeds remaining buffer {1}")]
    BodyOverflow(u32, usize),

    #[error("inner aes_enable byte = {0}, must be 0 or 1")]
    InvalidAesFlag(u8),

    #[error("crc32 mismatch on {0}: stored {1:#010x}, computed {2:#010x}")]
    CrcMismatch(&'static str, u32, u32),
}

/// Parsed AUP header (any of `fmt_ver` 0 / 1 / 2).
///
/// Field offsets differ per version; `parse` dispatches on `fmt_ver` and normalises
/// every version into this common shape. `body_len` == the spec's `payload_len`
/// (name kept for back-compat). New fields (`payload_crc`, `header_size`, `hw_list`,
/// `sw_list`) are populated for every version — `hw_list`/`sw_list` are empty for v0,
/// and `sw_list` is empty for v1 (v1 carries a single comma-separated hw list only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AupHeader {
    pub fmt_ver: u8,
    pub body_len: u32,
    /// 64-byte `firmware_ver` ASCII string, NUL-padded (§3.1 line 76).
    pub firmware_ver: [u8; AUP_FIRMWARE_VER_SIZE],
    /// `payload_crc32` field value (zlib.crc32 over the payload), verbatim from the
    /// version-appropriate offset (v0/v2 @ 0x58, v1 @ 0xDC).
    pub payload_crc: u32,
    /// True header size in bytes = the offset at which the body/payload begins.
    /// v0 = 92, v1 = 224, v2 = `100 + 32*(hw+sw) + 4` (variable).
    pub header_size: usize,
    /// Compatible hardware-type strings. v0: empty. v1: the comma-separated
    /// `hw_list_str` split into entries. v2: the `Fixed32Str hw_list[]` array.
    pub hw_list: Vec<String>,
    /// Compatible software-type strings. Only v2 carries these (`Fixed32Str sw_list[]`);
    /// empty for v0/v1.
    pub sw_list: Vec<String>,
}

impl AupHeader {
    /// True whether the given `hwtype`/`swtype` reported by a target miner is accepted
    /// by this package's compatibility lists — the brick-prevention gate.
    ///
    /// - **v0** has no compatibility list → always compatible.
    /// - **v1** gates on `hwtype ∈ hw_list` (no software list exists).
    /// - **v2** gates on `hwtype ∈ hw_list` AND `swtype ∈ sw_list`.
    pub fn is_compatible(&self, hwtype: &str, swtype: &str) -> bool {
        match self.fmt_ver {
            0 => true,
            1 => self.hw_list.iter().any(|h| h == hwtype),
            _ => {
                self.hw_list.iter().any(|h| h == hwtype) && self.sw_list.iter().any(|s| s == swtype)
            }
        }
    }

    /// Offset at which the body/payload begins (== `header_size`). Kept as a method
    /// so callers can slice `buf[hdr.body_offset()..]` without re-deriving the size.
    pub fn body_offset(&self) -> usize {
        self.header_size
    }

    /// Full `firmware_ver` string (e.g. "24041001_08b0955_0196aba") as best-effort
    /// UTF-8, trimming trailing NUL padding.
    pub fn firmware_ver_str(&self) -> &str {
        let end = self
            .firmware_ver
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(AUP_FIRMWARE_VER_SIZE);
        core::str::from_utf8(&self.firmware_ver[..end]).unwrap_or("")
    }

    /// Back-compat alias: the historical 8-byte "tag" (first 8 bytes of
    /// `firmware_ver`). Prefer `firmware_ver_str()` — this truncates to 8 bytes.
    pub fn tag_str(&self) -> &str {
        let n = AUP_TAG_SIZE.min(AUP_FIRMWARE_VER_SIZE);
        let end = self.firmware_ver[..n]
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(n);
        core::str::from_utf8(&self.firmware_ver[..end]).unwrap_or("")
    }

    /// Parse an AUP header of any supported `fmt_ver` (0, 1, or 2).
    ///
    /// Dispatches on the `fmt_ver` field @ 0x10 and reads each version with its OWN
    /// offset set — reading a real v0/v1 package at the v2 absolute offsets silently
    /// mis-parses it (that was defect #1). Intentionally **permissive about `body_len`**:
    /// the returned `body_len` is verbatim and unbounded; callers that slice the body
    /// MUST validate first via `parse_full` / `validate_body_len`.
    pub fn parse(buf: &[u8]) -> Result<Self, AupError> {
        if buf.len() < AUP_MIN_HEADER_SIZE {
            return Err(AupError::ShortBuffer(buf.len()));
        }
        let mut magic_observed = [0u8; 16];
        magic_observed.copy_from_slice(&buf[..16]);
        if &magic_observed != AUP_MAGIC {
            return Err(AupError::BadMagic(magic_observed));
        }
        match buf[AUP_FMT_VER_OFFSET] {
            0 => Self::parse_v0(buf),
            1 => Self::parse_v1(buf),
            2 => Self::parse_v2(buf),
            other => Err(AupError::UnsupportedFmtVer(other)),
        }
    }

    /// `fmt_ver == 0` (92-byte header): payload_len @0x14, firmware_ver[64] @0x18,
    /// payload_crc @0x58. No hw/sw compatibility lists.
    fn parse_v0(buf: &[u8]) -> Result<Self, AupError> {
        if buf.len() < AUP_V0_HEADER_SIZE {
            return Err(AupError::ShortBuffer(buf.len()));
        }
        Ok(Self {
            fmt_ver: 0,
            body_len: read_u32_le(buf, AUP_BODY_LEN_OFFSET),
            firmware_ver: read_firmware_ver(buf, AUP_FIRMWARE_VER_OFFSET),
            payload_crc: read_u32_le(buf, AUP_PAYLOAD_CRC32_OFFSET),
            header_size: AUP_V0_HEADER_SIZE,
            hw_list: Vec::new(),
            sw_list: Vec::new(),
        })
    }

    /// `fmt_ver == 1` (224-byte header): header_len @0x14, hw_list_str[128] @0x18
    /// (comma-separated), payload_len @0x98, firmware_ver[64] @0x9C, payload_crc @0xDC.
    /// Every field after the 128-byte hw_list_str is shifted vs v0/v2 — hence its own
    /// offset set.
    fn parse_v1(buf: &[u8]) -> Result<Self, AupError> {
        if buf.len() < AUP_V1_HEADER_SIZE {
            return Err(AupError::ShortBuffer(buf.len()));
        }
        let hw_list = parse_comma_list(
            &buf[AUP_V1_HW_LIST_STR_OFFSET..AUP_V1_HW_LIST_STR_OFFSET + AUP_V1_HW_LIST_STR_SIZE],
        );
        Ok(Self {
            fmt_ver: 1,
            body_len: read_u32_le(buf, AUP_V1_PAYLOAD_LEN_OFFSET),
            firmware_ver: read_firmware_ver(buf, AUP_V1_FIRMWARE_VER_OFFSET),
            payload_crc: read_u32_le(buf, AUP_V1_PAYLOAD_CRC32_OFFSET),
            header_size: AUP_V1_HEADER_SIZE,
            hw_list,
            sw_list: Vec::new(),
        })
    }

    /// `fmt_ver == 2` (variable header): the industrial K210 layout — payload_len @0x14,
    /// firmware_ver[64] @0x18, payload_crc @0x58, hw_count @0x5C, sw_count @0x60, then
    /// `Fixed32Str hw_list[]` / `sw_list[]` @0x64, then the 4-byte `header_crc`. The true
    /// `header_size` is the offset just past that CRC — computed from the list counts,
    /// NOT the pinned corpus constant (that was defect #2).
    fn parse_v2(buf: &[u8]) -> Result<Self, AupError> {
        let end = end_of_sw_list(buf)?; // validates the declared counts fit in `buf`
        let header_size = end + 4; // + the trailing 4-byte header_crc field
        let hw_count = read_u32_le(buf, AUP_HW_LIST_COUNT_OFFSET) as usize;
        let sw_count = read_u32_le(buf, AUP_SW_LIST_COUNT_OFFSET) as usize;
        let mut off = AUP_LIST_BASE_OFFSET;
        let mut hw_list = Vec::with_capacity(hw_count);
        for _ in 0..hw_count {
            hw_list.push(read_fixed32(&buf[off..off + 32]));
            off += 32;
        }
        let mut sw_list = Vec::with_capacity(sw_count);
        for _ in 0..sw_count {
            sw_list.push(read_fixed32(&buf[off..off + 32]));
            off += 32;
        }
        Ok(Self {
            fmt_ver: 2,
            body_len: read_u32_le(buf, AUP_BODY_LEN_OFFSET),
            firmware_ver: read_firmware_ver(buf, AUP_FIRMWARE_VER_OFFSET),
            payload_crc: read_u32_le(buf, AUP_PAYLOAD_CRC32_OFFSET),
            header_size,
            hw_list,
            sw_list,
        })
    }

    /// Parse the header AND validate `body_len` against the supplied whole-image
    /// buffer. Use this when `buf` is the entire image (header + body), not just
    /// the 200-byte header. Returns `BodyOverflow` if `body_len` would run past
    /// the end of the buffer.
    pub fn parse_full(buf: &[u8]) -> Result<Self, AupError> {
        let hdr = Self::parse(buf)?;
        hdr.validate_body_len(buf.len())?;
        Ok(hdr)
    }

    /// Check that `body_len` fits in the bytes available after the header in a
    /// whole-image buffer of length `buf_len`. Additive guard for callers that
    /// slice `buf[self.body_offset()..][..body_len]`. Uses the parsed, per-version
    /// `header_size` (NOT the pinned v2-corpus `AUP_BODY_OFFSET`), so it is correct
    /// for v0 (92) / v1 (224) / any v2 hw+sw count.
    pub fn validate_body_len(&self, buf_len: usize) -> Result<(), AupError> {
        let avail = buf_len.saturating_sub(self.header_size);
        if self.body_len as usize > avail {
            return Err(AupError::BodyOverflow(self.body_len, avail));
        }
        Ok(())
    }

    /// Verify the `header_crc32` field (zlib.crc32 over `[0 .. end_of_sw_list]`,
    /// §3.1 line 82). The 4-byte CRC field sits at `end_of_sw_list`, which is
    /// computed from the header's own `hw_list_count`/`sw_list_count` (so this
    /// also works for non-corpus list counts, not just the 200-byte corpus).
    pub fn verify_header_crc(buf: &[u8]) -> Result<(), AupError> {
        let end = end_of_sw_list(buf)?;
        let stored = read_u32_le(buf, end);
        let computed = crc32(&buf[..end]);
        if stored != computed {
            return Err(AupError::CrcMismatch("header", stored, computed));
        }
        Ok(())
    }

    /// Verify the `payload_crc32` field (u32 LE @ 0x58, §3.1 line 77) — zlib.crc32
    /// over the encrypted payload, i.e. `buf[body_off .. body_off + payload_len]`
    /// where `body_off = end_of_sw_list + 4` and `payload_len` is the field @ 0x14.
    pub fn verify_payload_crc(buf: &[u8]) -> Result<(), AupError> {
        let body_off = end_of_sw_list(buf)? + 4;
        let payload_len = read_u32_le(buf, AUP_BODY_LEN_OFFSET) as usize;
        let end = body_off
            .checked_add(payload_len)
            .filter(|&e| e <= buf.len())
            .ok_or(AupError::BodyOverflow(payload_len as u32, buf.len()))?;
        let stored = read_u32_le(buf, AUP_PAYLOAD_CRC32_OFFSET);
        let computed = crc32(&buf[body_off..end]);
        if stored != computed {
            return Err(AupError::CrcMismatch("payload", stored, computed));
        }
        Ok(())
    }
}

/// Read a little-endian u32 at `off` (caller guarantees `off + 4 <= buf.len()`).
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Copy the 64-byte `firmware_ver` field starting at `off` (caller guarantees room).
fn read_firmware_ver(buf: &[u8], off: usize) -> [u8; AUP_FIRMWARE_VER_SIZE] {
    let mut fw = [0u8; AUP_FIRMWARE_VER_SIZE];
    fw.copy_from_slice(&buf[off..off + AUP_FIRMWARE_VER_SIZE]);
    fw
}

/// Split a NUL-terminated, comma-separated fixed-width field (v1 `hw_list_str`) into
/// trimmed, non-empty entries.
fn parse_comma_list(field: &[u8]) -> Vec<String> {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    core::str::from_utf8(&field[..end])
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Decode one 32-byte NUL-padded `Fixed32Str` (v2 hw/sw list entry) into a String.
fn read_fixed32(field: &[u8]) -> String {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    core::str::from_utf8(&field[..end])
        .unwrap_or("")
        .to_string()
}

/// Compute `end_of_sw_list` (the offset of the `header_crc32` field) from the
/// header's declared `hw_list_count`/`sw_list_count`, per §3.1 lines 78-82:
/// `0x64 + 32*hw_list_count + 32*sw_list_count`. Validates that the declared
/// layout (including the trailing 4-byte CRC field) fits inside `buf`, so a
/// crafted huge count cannot trigger an OOB read or arithmetic overflow.
fn end_of_sw_list(buf: &[u8]) -> Result<usize, AupError> {
    if buf.len() < AUP_HEADER_SIZE {
        return Err(AupError::ShortBuffer(buf.len()));
    }
    let hw = read_u32_le(buf, AUP_HW_LIST_COUNT_OFFSET) as u64;
    let sw = read_u32_le(buf, AUP_SW_LIST_COUNT_OFFSET) as u64;
    let end = AUP_LIST_BASE_OFFSET as u64 + 32 * hw + 32 * sw;
    // Need `end + 4` bytes present for the header_crc32 field itself.
    let need = end + 4;
    if need > buf.len() as u64 {
        return Err(AupError::BodyOverflow(
            end.min(u32::MAX as u64) as u32,
            buf.len(),
        ));
    }
    Ok(end as usize)
}

/// Pure CRC-32 (IEEE 802.3 / zlib.crc32, reflected, poly 0xEDB88320). Matches
/// Python's `zlib.crc32`, which §3.1 names for both `header_crc32`/`payload_crc32`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Inner-body framing for industrial K210 firmware (post-header).
/// `ciphertext` length is `inner_size`; the trailing 32 B SHA-256 is NOT included here.
#[derive(Debug, Clone)]
pub struct AupBody<'a> {
    pub aes_enable: bool,
    pub inner_size: u32,
    pub ciphertext: &'a [u8],
    /// Trailing SHA-256 over (aes_enable_byte || size_LE || ciphertext).
    pub sha256_trailer: &'a [u8],
}

impl<'a> AupBody<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, AupError> {
        if buf.len() < 5 + 32 {
            return Err(AupError::ShortBuffer(buf.len()));
        }
        let aes_byte = buf[0];
        if aes_byte > 1 {
            return Err(AupError::InvalidAesFlag(aes_byte));
        }
        let inner_size = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let want = 5usize + inner_size as usize + 32;
        if buf.len() < want {
            return Err(AupError::BodyOverflow(inner_size, buf.len()));
        }
        Ok(Self {
            aes_enable: aes_byte == 1,
            inner_size,
            ciphertext: &buf[5..5 + inner_size as usize],
            sha256_trailer: &buf[5 + inner_size as usize..5 + inner_size as usize + 32],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_header(fmt_ver: u8, body_len: u32, tag: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; AUP_HEADER_SIZE];
        buf[..16].copy_from_slice(AUP_MAGIC);
        buf[AUP_FMT_VER_OFFSET] = fmt_ver;
        buf[AUP_BODY_LEN_OFFSET..AUP_BODY_LEN_OFFSET + 4].copy_from_slice(&body_len.to_le_bytes());
        // Historical 8-byte tag write (first bytes of firmware_ver region).
        let n = tag.len().min(AUP_TAG_SIZE);
        buf[AUP_TAG_OFFSET..AUP_TAG_OFFSET + n].copy_from_slice(&tag[..n]);
        buf
    }

    fn build_inner_body(aes_enable: u8, payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(aes_enable);
        b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        b.extend_from_slice(payload);
        b.extend_from_slice(&[0x55u8; 32]); // dummy SHA-256 trailer
        b
    }

    fn build_v0_header(payload_len: u32, fw: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; AUP_V0_HEADER_SIZE];
        buf[..16].copy_from_slice(AUP_MAGIC);
        buf[AUP_FMT_VER_OFFSET] = 0;
        buf[AUP_BODY_LEN_OFFSET..AUP_BODY_LEN_OFFSET + 4]
            .copy_from_slice(&payload_len.to_le_bytes());
        let n = fw.len().min(AUP_FIRMWARE_VER_SIZE);
        buf[AUP_FIRMWARE_VER_OFFSET..AUP_FIRMWARE_VER_OFFSET + n].copy_from_slice(&fw[..n]);
        buf
    }

    fn build_v1_header(payload_len: u32, fw: &[u8], hw_list_str: &str) -> Vec<u8> {
        let mut buf = vec![0u8; AUP_V1_HEADER_SIZE];
        buf[..16].copy_from_slice(AUP_MAGIC);
        buf[AUP_FMT_VER_OFFSET] = 1;
        buf[AUP_V1_HEADER_LEN_OFFSET..AUP_V1_HEADER_LEN_OFFSET + 4]
            .copy_from_slice(&(AUP_V1_HEADER_SIZE as u32).to_le_bytes());
        let h = hw_list_str.as_bytes();
        let hn = h.len().min(AUP_V1_HW_LIST_STR_SIZE);
        buf[AUP_V1_HW_LIST_STR_OFFSET..AUP_V1_HW_LIST_STR_OFFSET + hn].copy_from_slice(&h[..hn]);
        buf[AUP_V1_PAYLOAD_LEN_OFFSET..AUP_V1_PAYLOAD_LEN_OFFSET + 4]
            .copy_from_slice(&payload_len.to_le_bytes());
        let n = fw.len().min(AUP_FIRMWARE_VER_SIZE);
        buf[AUP_V1_FIRMWARE_VER_OFFSET..AUP_V1_FIRMWARE_VER_OFFSET + n].copy_from_slice(&fw[..n]);
        buf
    }

    // ---- existing 4 tests (unchanged behavior) ----

    #[test]
    fn parses_minimal_v2_header() {
        let buf = build_header(0x02, 0x9A9B8, b"miner");
        let h = AupHeader::parse(&buf).unwrap();
        assert_eq!(h.fmt_ver, 0x02);
        assert_eq!(h.body_len, 0x9A9B8);
        assert_eq!(h.tag_str(), "miner");
    }

    #[test]
    fn v2_header_matches_literal_offset_golden() {
        let mut buf = build_header(0x02, 69, b"x");
        let ver = b"24041001_08b0955_0196aba";
        buf[AUP_FIRMWARE_VER_OFFSET..AUP_FIRMWARE_VER_OFFSET + ver.len()].copy_from_slice(ver);
        buf[AUP_HW_LIST_COUNT_OFFSET..AUP_HW_LIST_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        buf[AUP_SW_LIST_COUNT_OFFSET..AUP_SW_LIST_COUNT_OFFSET + 4]
            .copy_from_slice(&2u32.to_le_bytes());

        assert_eq!(
            &buf[..0x18],
            &[
                b'A', b'U', b'P', b' ', b'f', b'o', b'r', b'm', b'a', b't', 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 69, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(
            &buf[AUP_FIRMWARE_VER_OFFSET..AUP_FIRMWARE_VER_OFFSET + ver.len()],
            ver
        );
        assert_eq!(
            &buf[AUP_PAYLOAD_CRC32_OFFSET..AUP_PAYLOAD_CRC32_OFFSET + 4],
            &[0; 4]
        );
        assert_eq!(
            &buf[AUP_HW_LIST_COUNT_OFFSET..AUP_HW_LIST_COUNT_OFFSET + 8],
            &[1, 0, 0, 0, 2, 0, 0, 0]
        );
    }

    #[test]
    fn rejects_short_buffer() {
        let buf = [0u8; 50];
        assert!(matches!(
            AupHeader::parse(&buf),
            Err(AupError::ShortBuffer(50))
        ));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = vec![0u8; AUP_HEADER_SIZE];
        buf[..16].copy_from_slice(b"NOT-AUP-AT-ALL!!");
        assert!(matches!(AupHeader::parse(&buf), Err(AupError::BadMagic(_))));
    }

    #[test]
    fn rejects_future_fmt_ver() {
        let buf = build_header(0x09, 0, b"miner");
        assert!(matches!(
            AupHeader::parse(&buf),
            Err(AupError::UnsupportedFmtVer(9))
        ));
    }

    // ---- fmt_ver 0 / 1 dispatch (defect #1: v0/v1 were mis-parsed at v2 offsets) ----

    #[test]
    fn parses_v0_header() {
        let buf = build_v0_header(0x1234, b"19101501_f293f38_2fbfeda");
        let h = AupHeader::parse(&buf).unwrap();
        assert_eq!(h.fmt_ver, 0);
        assert_eq!(h.body_len, 0x1234);
        assert_eq!(h.header_size, 92);
        assert_eq!(h.firmware_ver_str(), "19101501_f293f38_2fbfeda");
        assert!(h.hw_list.is_empty() && h.sw_list.is_empty());
        // v0 has no compat list → always compatible.
        assert!(h.is_compatible("any-hw", "any-sw"));
    }

    #[test]
    fn parses_v1_header_with_hw_list() {
        let buf = build_v1_header(0x2000, b"20010101_abc_def", "MM3v1_X3,MM5v1");
        let h = AupHeader::parse(&buf).unwrap();
        assert_eq!(h.fmt_ver, 1);
        assert_eq!(h.body_len, 0x2000);
        assert_eq!(h.header_size, 224);
        assert_eq!(h.firmware_ver_str(), "20010101_abc_def");
        assert_eq!(h.hw_list, vec!["MM3v1_X3".to_string(), "MM5v1".to_string()]);
        assert!(h.sw_list.is_empty());
        assert!(h.is_compatible("MM5v1", "ignored")); // v1 gates on hw only
        assert!(!h.is_compatible("MM7v9", "ignored"));
    }

    #[test]
    fn v1_is_not_misparsed_at_v2_offsets() {
        // Correct v1 parsing reads payload_len @0x98 (=0x40), NOT the header_len @0x14.
        // The old v2-offset code returned the header_len (224) here — that was the bug.
        let buf = build_v1_header(0x40, b"fw", "MM3v1_X3");
        let h = AupHeader::parse(&buf).unwrap();
        assert_eq!(h.body_len, 0x40);
        assert_ne!(h.body_len, AUP_V1_HEADER_SIZE as u32);
    }

    #[test]
    fn short_v1_buffer_reports_shortbuffer() {
        // A 92-byte buffer that *claims* fmt_ver 1 is too short for the 224-byte v1 header.
        let mut buf = build_v0_header(0, b"x");
        buf[AUP_FMT_VER_OFFSET] = 1;
        assert!(matches!(
            AupHeader::parse(&buf),
            Err(AupError::ShortBuffer(92))
        ));
    }

    #[test]
    fn v2_compat_gate_checks_both_hw_and_sw() {
        // v2 header with hw_list=[A1246], sw_list=[MM310].
        let mut buf = build_header(0x02, 100, b"fw");
        buf[AUP_HW_LIST_COUNT_OFFSET..AUP_HW_LIST_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        buf[AUP_SW_LIST_COUNT_OFFSET..AUP_SW_LIST_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        buf[AUP_LIST_BASE_OFFSET..AUP_LIST_BASE_OFFSET + 5].copy_from_slice(b"A1246");
        buf[AUP_LIST_BASE_OFFSET + 32..AUP_LIST_BASE_OFFSET + 32 + 5].copy_from_slice(b"MM310");
        let h = AupHeader::parse(&buf).unwrap();
        assert_eq!(h.hw_list, vec!["A1246".to_string()]);
        assert_eq!(h.sw_list, vec!["MM310".to_string()]);
        // header_size computed from counts: 0x64 + 32 + 32 + 4 = 168.
        assert_eq!(h.header_size, 168);
        assert_eq!(h.body_offset(), 168);
        assert!(h.is_compatible("A1246", "MM310"));
        assert!(!h.is_compatible("A1246", "MM999")); // sw mismatch
        assert!(!h.is_compatible("A9999", "MM310")); // hw mismatch
    }

    // ---- Task 1: AUP_BODY_OFFSET framing-corruption fix ----

    #[test]
    fn body_offset_equals_header_size() {
        // Const-evaluated guard mirrors the module-level `const _` assertions.
        const _: () = assert!(AUP_BODY_OFFSET == AUP_HEADER_SIZE);
        assert_eq!(AUP_BODY_OFFSET, AUP_HEADER_SIZE);
        assert_eq!(AUP_BODY_OFFSET, 0xC8);
        // Corpus header-size formula sanity (§3.1 line 86: 1 hw + 2 sw → 200).
        assert_eq!(aup_header_size(1, 2), AUP_HEADER_SIZE);
    }

    #[test]
    fn body_offset_slices_inner_k210_body_correctly() {
        // 200-byte header + a valid K210 inner body. At the OLD 0xBC=188 offset the
        // parser would feed the 12 trailing (zeroed) header bytes into
        // AupBody::parse and mis-read aes_enable + inner_size.
        let n = 48usize;
        let payload = vec![0xABu8; n];
        let body = build_inner_body(0, &payload);
        let mut buf = build_header(0x02, body.len() as u32, b"miner");
        buf.extend_from_slice(&body);

        let parsed = AupBody::parse(&buf[AUP_BODY_OFFSET..]).unwrap();
        assert!(!parsed.aes_enable);
        assert_eq!(parsed.inner_size, n as u32);
        assert_eq!(parsed.ciphertext.len(), n);
        assert_eq!(parsed.ciphertext, &payload[..]);

        // Demonstrate the bug the fix closes: at the OLD 0xBC (188) offset the
        // parser mis-reads the 12-byte zeroed header tail as the body framing.
        let wrong = AupBody::parse(&buf[0xBC..]).unwrap();
        assert_eq!(wrong.inner_size, 0); // header-tail zeros, NOT the real 48
        assert_ne!(wrong.inner_size, parsed.inner_size);
    }

    // ---- Task 2: bound payload_len (fail-open header parser) ----

    #[test]
    fn header_only_parse_is_permissive_about_body_len() {
        // Documents the permissive header-only contract: parse() does NOT bound
        // body_len, so a 200-byte header declaring u32::MAX still parses OK.
        let buf = build_header(0x02, u32::MAX, b"miner");
        let h = AupHeader::parse(&buf).unwrap();
        assert_eq!(h.body_len, u32::MAX);
    }

    #[test]
    fn parse_full_rejects_oversized_body_len() {
        let buf = build_header(0x02, u32::MAX, b"miner"); // 200-byte buf, huge body_len
        assert!(matches!(
            AupHeader::parse_full(&buf),
            Err(AupError::BodyOverflow(_, _))
        ));
        // Helper form rejects too.
        let h = AupHeader::parse(&buf).unwrap();
        assert!(matches!(
            h.validate_body_len(buf.len()),
            Err(AupError::BodyOverflow(_, _))
        ));
    }

    #[test]
    fn parse_full_accepts_in_bounds_body_len() {
        let n = 16usize;
        let body = build_inner_body(0, &vec![0u8; n]); // len = 5 + n + 32
        let mut buf = build_header(0x02, body.len() as u32, b"miner");
        buf.extend_from_slice(&body);
        let h = AupHeader::parse_full(&buf).unwrap();
        assert_eq!(h.body_len as usize, 5 + n + 32);
        assert!(h.validate_body_len(buf.len()).is_ok());
    }

    // ---- Task 3: 64-byte firmware_ver field ----

    #[test]
    fn firmware_ver_str_returns_full_64_byte_string() {
        let ver = b"24041001_08b0955_0196aba"; // 24 chars — past the old 8-byte tag
        let mut buf = build_header(0x02, 0, b"x");
        buf[AUP_FIRMWARE_VER_OFFSET..AUP_FIRMWARE_VER_OFFSET + ver.len()].copy_from_slice(ver);
        let h = AupHeader::parse(&buf).unwrap();
        assert_eq!(h.firmware_ver_str(), "24041001_08b0955_0196aba");
        // Old 8-byte alias truncates (documents the historical, lossy behavior).
        assert_eq!(h.tag_str(), "24041001");
    }

    // ---- Task 4: AupBody coverage + CRC helpers ----

    #[test]
    fn aup_body_plaintext_roundtrip() {
        let payload = [0xDEu8; 40];
        let body = build_inner_body(0, &payload);
        let p = AupBody::parse(&body).unwrap();
        assert!(!p.aes_enable);
        assert_eq!(p.inner_size, 40);
        assert_eq!(p.ciphertext, &payload[..]);
        assert_eq!(p.sha256_trailer.len(), 32);
    }

    #[test]
    fn aup_body_aes_roundtrip() {
        let payload = [0x77u8; 64];
        let body = build_inner_body(1, &payload);
        let p = AupBody::parse(&body).unwrap();
        assert!(p.aes_enable);
        assert_eq!(p.inner_size, 64);
        assert_eq!(p.ciphertext, &payload[..]);
    }

    #[test]
    fn aup_body_rejects_short_buffer() {
        let body = [0u8; 36]; // < 5 + 32
        assert!(matches!(
            AupBody::parse(&body),
            Err(AupError::ShortBuffer(36))
        ));
    }

    #[test]
    fn aup_body_rejects_invalid_aes_flag() {
        let mut body = build_inner_body(0, &[0u8; 8]);
        body[0] = 2;
        assert!(matches!(
            AupBody::parse(&body),
            Err(AupError::InvalidAesFlag(2))
        ));
    }

    #[test]
    fn aup_body_rejects_overflow_inner_size() {
        // inner_size claims 1000 but the buffer only has room for 10 payload bytes.
        let mut body = vec![0u8; 5 + 10 + 32];
        body[0] = 0;
        body[1..5].copy_from_slice(&1000u32.to_le_bytes());
        assert!(matches!(
            AupBody::parse(&body),
            Err(AupError::BodyOverflow(1000, _))
        ));
    }

    #[test]
    fn crc32_matches_known_check_vector() {
        // Standard CRC-32 check value: zlib.crc32(b"123456789") == 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0x0000_0000);
    }

    #[test]
    fn verify_crcs_on_synthesized_image() {
        let payload = [0x5Au8; 32];
        let body = build_inner_body(0, &payload); // len 5 + 32 + 32 = 69
        let mut buf = build_header(0x02, body.len() as u32, b"miner");
        // 1 hw + 2 sw → computed header size == 200 (corpus layout).
        buf[AUP_HW_LIST_COUNT_OFFSET..AUP_HW_LIST_COUNT_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        buf[AUP_SW_LIST_COUNT_OFFSET..AUP_SW_LIST_COUNT_OFFSET + 4]
            .copy_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&body);

        // payload_crc32 @ 0x58 over the body.
        let pcrc = crc32(&body);
        buf[AUP_PAYLOAD_CRC32_OFFSET..AUP_PAYLOAD_CRC32_OFFSET + 4]
            .copy_from_slice(&pcrc.to_le_bytes());
        // header_crc32 @ end_of_sw_list (196) over [0..196] — set LAST.
        let hcrc = crc32(&buf[..AUP_HEADER_SIZE - 4]);
        buf[AUP_HEADER_SIZE - 4..AUP_HEADER_SIZE].copy_from_slice(&hcrc.to_le_bytes());

        AupHeader::verify_header_crc(&buf).unwrap();
        AupHeader::verify_payload_crc(&buf).unwrap();

        // Corrupt a payload byte → payload CRC fails.
        let mut bad = buf.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert!(matches!(
            AupHeader::verify_payload_crc(&bad),
            Err(AupError::CrcMismatch("payload", _, _))
        ));

        // Corrupt a header byte (reserved pad @ 0x11) → header CRC fails.
        let mut bad2 = buf.clone();
        bad2[0x11] ^= 0xFF;
        assert!(matches!(
            AupHeader::verify_header_crc(&bad2),
            Err(AupError::CrcMismatch("header", _, _))
        ));
    }
}
