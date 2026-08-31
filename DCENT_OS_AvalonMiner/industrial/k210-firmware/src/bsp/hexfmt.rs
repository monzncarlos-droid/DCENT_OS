//! Allocation-free hexadecimal formatting for early-boot evidence beacons.

/// Lowercase, fixed-width representation of one `u32` with no `0x` prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HexU32([u8; 8]);

impl HexU32 {
    #[must_use]
    pub const fn new(value: u32) -> Self {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = [b'0'; 8];
        let mut index = 0;
        while index < output.len() {
            let shift = (7 - index) * 4;
            output[index] = DIGITS[((value >> shift) & 0x0f) as usize];
            index += 1;
        }
        Self(output)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_width_lowercase_is_deterministic() {
        assert_eq!(HexU32::new(0).as_bytes(), b"00000000");
        assert_eq!(HexU32::new(0x12ab_cdef).as_bytes(), b"12abcdef");
        assert_eq!(HexU32::new(u32::MAX).as_bytes(), b"ffffffff");
    }
}
