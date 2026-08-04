// DCENT_axe — host-side scrypt(N, r, p) proof-of-work core
// Copyright (C) 2026 D-Central Technologies
// License: GPL-3.0
//
// P2 of `docs/SCRYPT_STACK_DESIGN.md`. Clean-room implementation of RFC 7914
// scrypt, used ONLY for host-side share verification of Litecoin/scrypt work
// (`scrypt(N=1024, r=1, p=1)` over the 80-byte block header, password == salt).
//
// The ASIC does 100% of the mining. This module exists for exactly one reason:
// the HW-error classifier / pool-ban shield that `full_header_difficulty_and_target`
// already provides for SHA-256 must exist for Scrypt too, or we would be
// submitting unverified ASIC output to a pool (design §2.5, option "no
// verification" is explicitly rejected).
//
// ── Memory posture (design §2.5 / R9) ───────────────────────────────────────
// scrypt(N=1024, r=1) needs a 128 KiB `V` scratchpad. On an ESP32-S3 with
// ~300 KB usable that must be ONE allocation reused forever, never a per-nonce
// allocation. [`with_scratch`] owns a thread-local, lazily-allocated buffer;
// [`prewarm`] forces the allocation up front (called by the mining dispatcher
// when it is configured for a Scrypt algorithm) so a mid-mining OOM cannot
// surprise the RX drain path. If the allocation fails, verification fails
// CLOSED (no share) rather than passing an unverified nonce.

use std::cell::RefCell;

use sha2::{Digest, Sha256};

/// Litecoin proof-of-work cost parameter.
pub const LTC_N: u32 = 1024;
/// Litecoin proof-of-work block-size parameter.
pub const LTC_R: u32 = 1;
/// Litecoin proof-of-work parallelisation parameter.
pub const LTC_P: u32 = 1;

/// Bytes of `V` scratchpad required by `scrypt(N=1024, r=1)`: `128 * r * N`.
pub const LTC_SCRATCH_LEN: usize = 128 * (LTC_R as usize) * (LTC_N as usize); // 131072

/// Errors from the scrypt core. All are programmer/environment errors, never
/// "this nonce is bad" — a bad nonce is expressed as a low difficulty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScryptError {
    /// `N` is not a power of two greater than 1.
    InvalidCostParameter,
    /// Caller-supplied scratchpad is smaller than `128 * r * N`.
    ScratchTooSmall,
    /// The one-time 128 KiB scratchpad could not be allocated.
    ScratchAllocationFailed,
}

impl core::fmt::Display for ScryptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ScryptError::InvalidCostParameter => write!(f, "scrypt N must be a power of two > 1"),
            ScryptError::ScratchTooSmall => write!(f, "scrypt scratchpad too small (need 128*r*N)"),
            ScryptError::ScratchAllocationFailed => {
                write!(f, "scrypt scratchpad allocation failed")
            }
        }
    }
}

// ── HMAC-SHA256 / PBKDF2 ────────────────────────────────────────────────────
//
// Implemented inline rather than pulling `hmac`/`pbkdf2` crates: the crate
// already depends on `sha2`, the construction is 20 lines, and every extra
// dependency costs OTA-slot bytes on a partition that is ~89% full.

const SHA256_BLOCK: usize = 64;
const SHA256_OUT: usize = 32;

struct HmacSha256 {
    inner: Sha256,
    opad: [u8; SHA256_BLOCK],
}

impl HmacSha256 {
    fn new(key: &[u8]) -> Self {
        let mut block = [0u8; SHA256_BLOCK];
        if key.len() > SHA256_BLOCK {
            let digest = Sha256::digest(key);
            block[..SHA256_OUT].copy_from_slice(&digest);
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; SHA256_BLOCK];
        let mut opad = [0x5Cu8; SHA256_BLOCK];
        for i in 0..SHA256_BLOCK {
            ipad[i] ^= block[i];
            opad[i] ^= block[i];
        }
        let mut inner = Sha256::new();
        inner.update(ipad);
        Self { inner, opad }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> [u8; SHA256_OUT] {
        let inner = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(self.opad);
        outer.update(inner);
        let out = outer.finalize();
        let mut result = [0u8; SHA256_OUT];
        result.copy_from_slice(&out);
        result
    }
}

/// PBKDF2-HMAC-SHA256 with `c = 1`, the only iteration count scrypt uses.
///
/// With `c = 1` each output block is a single HMAC, so no accumulation loop is
/// needed. Written narrowly on purpose: a general PBKDF2 would be dead code.
fn pbkdf2_hmac_sha256_c1(password: &[u8], salt: &[u8], out: &mut [u8]) {
    let mut block_index: u32 = 1;
    let mut written = 0usize;
    while written < out.len() {
        let mut mac = HmacSha256::new(password);
        mac.update(salt);
        mac.update(&block_index.to_be_bytes());
        let u = mac.finalize();
        let take = (out.len() - written).min(SHA256_OUT);
        out[written..written + take].copy_from_slice(&u[..take]);
        written += take;
        block_index += 1;
    }
}

// ── Salsa20/8 core ──────────────────────────────────────────────────────────

/// Salsa20/8 core over a 64-byte block, in place (RFC 7914 §3).
fn salsa20_8(block: &mut [u8; 64]) {
    let mut x = [0u32; 16];
    for (i, w) in x.iter_mut().enumerate() {
        *w = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    let input = x;

    // 8 rounds = 4 double-rounds (column round + row round), written out
    // rather than macro-generated so the index pattern is auditable against
    // RFC 7914 §3 line by line.
    for _ in 0..4 {
        // column round
        x[4] ^= x[0].wrapping_add(x[12]).rotate_left(7);
        x[8] ^= x[4].wrapping_add(x[0]).rotate_left(9);
        x[12] ^= x[8].wrapping_add(x[4]).rotate_left(13);
        x[0] ^= x[12].wrapping_add(x[8]).rotate_left(18);

        x[9] ^= x[5].wrapping_add(x[1]).rotate_left(7);
        x[13] ^= x[9].wrapping_add(x[5]).rotate_left(9);
        x[1] ^= x[13].wrapping_add(x[9]).rotate_left(13);
        x[5] ^= x[1].wrapping_add(x[13]).rotate_left(18);

        x[14] ^= x[10].wrapping_add(x[6]).rotate_left(7);
        x[2] ^= x[14].wrapping_add(x[10]).rotate_left(9);
        x[6] ^= x[2].wrapping_add(x[14]).rotate_left(13);
        x[10] ^= x[6].wrapping_add(x[2]).rotate_left(18);

        x[3] ^= x[15].wrapping_add(x[11]).rotate_left(7);
        x[7] ^= x[3].wrapping_add(x[15]).rotate_left(9);
        x[11] ^= x[7].wrapping_add(x[3]).rotate_left(13);
        x[15] ^= x[11].wrapping_add(x[7]).rotate_left(18);

        // row round
        x[1] ^= x[0].wrapping_add(x[3]).rotate_left(7);
        x[2] ^= x[1].wrapping_add(x[0]).rotate_left(9);
        x[3] ^= x[2].wrapping_add(x[1]).rotate_left(13);
        x[0] ^= x[3].wrapping_add(x[2]).rotate_left(18);

        x[6] ^= x[5].wrapping_add(x[4]).rotate_left(7);
        x[7] ^= x[6].wrapping_add(x[5]).rotate_left(9);
        x[4] ^= x[7].wrapping_add(x[6]).rotate_left(13);
        x[5] ^= x[4].wrapping_add(x[7]).rotate_left(18);

        x[11] ^= x[10].wrapping_add(x[9]).rotate_left(7);
        x[8] ^= x[11].wrapping_add(x[10]).rotate_left(9);
        x[9] ^= x[8].wrapping_add(x[11]).rotate_left(13);
        x[10] ^= x[9].wrapping_add(x[8]).rotate_left(18);

        x[12] ^= x[15].wrapping_add(x[14]).rotate_left(7);
        x[13] ^= x[12].wrapping_add(x[15]).rotate_left(9);
        x[14] ^= x[13].wrapping_add(x[12]).rotate_left(13);
        x[15] ^= x[14].wrapping_add(x[13]).rotate_left(18);
    }

    for i in 0..16 {
        let v = x[i].wrapping_add(input[i]);
        block[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
}

/// `scryptBlockMix` (RFC 7914 §4) over `2r` 64-byte blocks, in place.
fn block_mix(b: &mut [u8], y: &mut [u8], r: usize) {
    let two_r = 2 * r;
    let mut x = [0u8; 64];
    x.copy_from_slice(&b[(two_r - 1) * 64..two_r * 64]);
    for i in 0..two_r {
        for j in 0..64 {
            x[j] ^= b[i * 64 + j];
        }
        salsa20_8(&mut x);
        // Y[i] = X, but stored shuffled: even indices first, then odd.
        let dst = if i % 2 == 0 { i / 2 } else { r + i / 2 };
        y[dst * 64..dst * 64 + 64].copy_from_slice(&x);
    }
    b[..two_r * 64].copy_from_slice(&y[..two_r * 64]);
}

/// `scryptROMix` (RFC 7914 §5) over one `128 * r`-byte block.
fn ro_mix(b: &mut [u8], v: &mut [u8], y: &mut [u8], n: u32, r: usize) {
    let block_len = 128 * r;
    for i in 0..n as usize {
        v[i * block_len..(i + 1) * block_len].copy_from_slice(&b[..block_len]);
        block_mix(b, y, r);
    }
    for _ in 0..n {
        // Integerify: little-endian integer from the LAST 64-byte block.
        let off = block_len - 64;
        let j = u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) & (n - 1);
        let base = j as usize * block_len;
        for k in 0..block_len {
            b[k] ^= v[base + k];
        }
        block_mix(b, y, r);
    }
}

/// Full `scrypt(password, salt, N, r, p, dk_len)` writing into `out`.
///
/// `scratch` must be at least `128 * r * N` bytes and is fully overwritten.
/// The caller owns it so the 128 KiB Litecoin scratchpad can be a single
/// boot-time allocation (see [`with_scratch`]).
pub fn scrypt_into(
    password: &[u8],
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
    scratch: &mut [u8],
    out: &mut [u8],
) -> Result<(), ScryptError> {
    if n < 2 || !n.is_power_of_two() {
        return Err(ScryptError::InvalidCostParameter);
    }
    let r = r as usize;
    let p = p as usize;
    let block_len = 128 * r;
    if scratch.len() < block_len * n as usize {
        return Err(ScryptError::ScratchTooSmall);
    }

    // B: p blocks of 128*r bytes. Heap because p*128*r is unbounded in theory;
    // for Litecoin (p=1, r=1) it is exactly 128 bytes.
    let mut b = vec![0u8; p * block_len];
    pbkdf2_hmac_sha256_c1(password, salt, &mut b);

    let mut y = vec![0u8; block_len];
    for i in 0..p {
        ro_mix(
            &mut b[i * block_len..(i + 1) * block_len],
            scratch,
            &mut y,
            n,
            r,
        );
    }

    pbkdf2_hmac_sha256_c1(password, &b, out);
    Ok(())
}

// ── Shared 128 KiB scratchpad ───────────────────────────────────────────────

thread_local! {
    /// One 128 KiB `V` scratchpad per thread, allocated on first use and then
    /// reused forever. In production exactly one thread (the mining
    /// dispatcher) ever touches it.
    static LTC_SCRATCH: RefCell<Option<Box<[u8]>>> = const { RefCell::new(None) };
}

/// Run `f` with the shared Litecoin scratchpad.
///
/// Fails CLOSED (`ScratchAllocationFailed`) if the buffer cannot be
/// allocated — a caller must then treat the nonce as unverifiable and NOT
/// submit it.
pub fn with_scratch<T>(f: impl FnOnce(&mut [u8]) -> T) -> Result<T, ScryptError> {
    LTC_SCRATCH.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            // `vec![0; N]` aborts rather than returning on OOM under
            // panic=abort, so there is no fallible allocator to consult here;
            // the Result arm exists so the caller's fail-closed path is
            // expressed in the type and stays reachable if this is ever moved
            // to a fallible allocator.
            let buf = vec![0u8; LTC_SCRATCH_LEN].into_boxed_slice();
            if buf.len() < LTC_SCRATCH_LEN {
                return Err(ScryptError::ScratchAllocationFailed);
            }
            *slot = Some(buf);
        }
        let buf = slot.as_mut().ok_or(ScryptError::ScratchAllocationFailed)?;
        Ok(f(buf))
    })
}

/// Force the 128 KiB scratchpad allocation now (design §2.5: "one 128 KiB
/// scratchpad allocated once at boot", never per-nonce).
///
/// Called by `MiningDispatcher` when its `DispatcherConfig::algorithm` is a
/// Scrypt algorithm, so the allocation happens on the mining thread before the
/// first nonce arrives instead of inside the RX-drain critical path.
pub fn prewarm() -> Result<(), ScryptError> {
    with_scratch(|_| ())
}

/// True once this thread holds the scratchpad (test/diagnostic helper).
pub fn scratch_is_allocated() -> bool {
    LTC_SCRATCH.with(|cell| cell.borrow().is_some())
}

/// `scrypt(N=1024, r=1, p=1)` over an 80-byte Litecoin block header, with
/// `password == salt == header` — the Litecoin proof-of-work function.
///
/// Returns the 32-byte digest in the SAME little-endian-integer convention
/// Bitcoin uses for SHA-256d (byte 0 = least significant), so callers reverse
/// it before comparing against a big-endian share target.
pub fn ltc_pow_hash(header: &[u8; 80]) -> Result<[u8; 32], ScryptError> {
    with_scratch(|scratch| {
        let mut out = [0u8; 32];
        scrypt_into(header, header, LTC_N, LTC_R, LTC_P, scratch, &mut out)?;
        Ok(out)
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scrypt_vec(password: &[u8], salt: &[u8], n: u32, r: u32, p: u32, dk_len: usize) -> Vec<u8> {
        let mut scratch = vec![0u8; 128 * r as usize * n as usize];
        let mut out = vec![0u8; dk_len];
        scrypt_into(password, salt, n, r, p, &mut scratch, &mut out).expect("scrypt");
        out
    }

    // ── RFC 7914 §12 published test vectors ─────────────────────────────────
    //
    // Vector 1 exercises r=1 — the EXACT Litecoin block-mix shape — so it is
    // the load-bearing one for this project. Vector 2 (r=8, p=16) additionally
    // exercises the p>1 loop and the odd/even block shuffle at r>1, which a
    // r=1-only implementation can get wrong invisibly.
    #[test]
    fn rfc7914_vector_1_empty_n16_r1_p1() {
        let expected: [u8; 64] = [
            0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a,
            0x04, 0x97, 0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8, 0xdf, 0xdf, 0xfa, 0x3f,
            0xed, 0xe2, 0x14, 0x42, 0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a,
            0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17, 0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
            0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06,
        ];
        assert_eq!(scrypt_vec(b"", b"", 16, 1, 1, 64), expected.to_vec());
    }

    #[test]
    fn rfc7914_vector_2_password_nacl_n1024_r8_p16() {
        let expected: [u8; 64] = [
            0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01,
            0xe9, 0xfe, 0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76, 0x63,
            0x4b, 0x37, 0x31, 0x62, 0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88, 0x6f, 0xf1,
            0x09, 0x27, 0x9d, 0x98, 0x30, 0xda, 0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
            0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40,
        ];
        assert_eq!(
            scrypt_vec(b"password", b"NaCl", 1024, 8, 16, 64),
            expected.to_vec()
        );
    }

    #[test]
    fn hmac_sha256_rfc4231_case_1() {
        // Independent pin on the inline HMAC: a wrong ipad/opad would still
        // produce a self-consistent (but wrong) scrypt.
        let mut mac = HmacSha256::new(&[0x0bu8; 20]);
        mac.update(b"Hi There");
        let out = mac.finalize();
        let expected: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn ltc_scratch_is_exactly_128_kib_and_reused() {
        assert_eq!(LTC_SCRATCH_LEN, 131_072);
        prewarm().expect("prewarm");
        assert!(scratch_is_allocated());
        // Second call must not re-allocate: the pointer identity is not
        // observable, but a second prewarm must still succeed and the buffer
        // must still serve a hash.
        prewarm().expect("prewarm again");
        let h = ltc_pow_hash(&[0u8; 80]).expect("hash");
        let h2 = ltc_pow_hash(&[0u8; 80]).expect("hash again");
        assert_eq!(h, h2, "scratchpad reuse must not corrupt the result");
    }

    #[test]
    fn ltc_pow_hash_is_deterministic_and_input_sensitive() {
        let mut header = [0u8; 80];
        let a = ltc_pow_hash(&header).expect("a");
        // Flip only the nonce (last 4 bytes) — the field the ASIC sweeps.
        header[79] = 1;
        let b = ltc_pow_hash(&header).expect("b");
        assert_ne!(a, b, "a nonce change must change the scrypt hash");
        assert_eq!(a, ltc_pow_hash(&[0u8; 80]).expect("a again"));
    }

    #[test]
    fn ltc_parameter_vector_matches_an_independent_openssl_oracle() {
        // Litecoin's EXACT parameters (N=1024, r=1, p=1, password==salt==the
        // 80-byte header) are not covered by any RFC vector, so this value was
        // produced by an INDEPENDENT implementation — CPython
        // `hashlib.scrypt` (OpenSSL), 2026-07-27:
        //   py -3 -c "import hashlib; h=bytes([0x5A]*80); \
        //     print(hashlib.scrypt(h,salt=h,n=1024,r=1,p=1,dklen=32).hex())"
        //   -> 9cf2bfd49091873711acaf8731fc8294ebc09335a22b92dfe71aef4a350b826a
        // Without this, RFC vector 1 (N=16) and vector 2 (r=8,p=16) leave the
        // N=1024/r=1/p=1 combination itself unpinned.
        let header = [0x5Au8; 80];
        let expected: [u8; 32] = [
            0x9c, 0xf2, 0xbf, 0xd4, 0x90, 0x91, 0x87, 0x37, 0x11, 0xac, 0xaf, 0x87, 0x31, 0xfc,
            0x82, 0x94, 0xeb, 0xc0, 0x93, 0x35, 0xa2, 0x2b, 0x92, 0xdf, 0xe7, 0x1a, 0xef, 0x4a,
            0x35, 0x0b, 0x82, 0x6a,
        ];
        assert_eq!(ltc_pow_hash(&header).expect("ltc hash"), expected);
    }

    #[test]
    fn ltc_pow_hash_matches_the_generic_core_with_litecoin_parameters() {
        // The convenience wrapper must be exactly scrypt(header, header,
        // 1024, 1, 1, 32) — password AND salt are the header (Litecoin's PoW),
        // not header/empty-salt.
        let header = [0x5Au8; 80];
        let via_wrapper = ltc_pow_hash(&header).expect("wrapper");
        let via_core = scrypt_vec(&header, &header, 1024, 1, 1, 32);
        assert_eq!(via_wrapper.to_vec(), via_core);
    }

    #[test]
    fn rejects_bad_cost_parameter_and_short_scratch() {
        let mut scratch = vec![0u8; 128];
        let mut out = [0u8; 32];
        assert_eq!(
            scrypt_into(b"", b"", 3, 1, 1, &mut scratch, &mut out),
            Err(ScryptError::InvalidCostParameter)
        );
        assert_eq!(
            scrypt_into(b"", b"", 1024, 1, 1, &mut scratch, &mut out),
            Err(ScryptError::ScratchTooSmall)
        );
    }
}
