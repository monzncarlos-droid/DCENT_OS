//! Hardware-neutral SHA-256 message padding used by stock FPGA job planners.

/// Append SHA-256's `0x80`, zero fill, and 64-bit big-endian bit length.
///
/// Returns `None` only when host-size or bit-length arithmetic overflows.
pub fn sha256_pad_message(message: &[u8]) -> Option<Vec<u8>> {
    let bit_len = u64::try_from(message.len()).ok()?.checked_mul(8)?;
    let with_suffix = message.len().checked_add(9)?;
    let padded_len = with_suffix.checked_add(63)? & !63;
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(message);
    padded.push(0x80);
    padded.resize(padded_len - 8, 0);
    padded.extend_from_slice(&bit_len.to_be_bytes());
    Some(padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_block_boundaries_match_recovered_job_padding() {
        for (raw_len, padded_len) in [
            (0, 64),
            (55, 64),
            (56, 128),
            (63, 128),
            (64, 128),
            (119, 128),
            (120, 192),
        ] {
            let raw = vec![0x5a; raw_len];
            let padded = sha256_pad_message(&raw).expect("bounded vector");
            assert_eq!(padded.len(), padded_len);
            assert_eq!(&padded[..raw_len], raw.as_slice());
            assert_eq!(padded[raw_len], 0x80);
            assert_eq!(
                &padded[padded_len - 8..],
                &u64::try_from(raw_len)
                    .unwrap()
                    .checked_mul(8)
                    .unwrap()
                    .to_be_bytes()
            );
        }
    }
}
