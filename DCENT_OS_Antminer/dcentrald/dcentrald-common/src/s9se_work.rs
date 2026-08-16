//! S9 SE VIL work-publication planner (desk-only).
//!
//! Stock `set_TW_write_command_vil` writes `i = 0..=12` (13 words).
//! `open_core_bm1393` allocates `buf_vil_tw[13]`. Issue #2's 12-word
//! `send_job` count is a different path and is **not** the SSOT.
//!
//! This module never writes `0x40`/`0x44` and never admits mining.

/// `set_TW_write_command_vil` loop `0..=12`.
pub const VIL_TW_WORDS: usize = 13;
/// First TW word: `axi[16] = 0x40`.
pub const TW_FIRST_OFFSET: u32 = 0x40;
/// Subsequent TW words: `axi[17] = 0x44`.
pub const TW_CONT_OFFSET: u32 = 0x44;
/// `set_dhash_acc_control(… | 0x8100)` raw-TW / freq-scan bit.
pub const DHASH_MODE_RAW_TW: u32 = 0x8100;
pub const DHASH_OFFSET: u32 = 0x100;
/// `send_job` first byte must be `82` (`0x52`). FPGA job type, not TW length.
pub const SEND_JOB_TYPE: u8 = 0x52;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeWorkError {
    TwelveWordSendJobIsNotSsot,
    WorkDispatchRefused,
    WrongBurstLength { observed: usize },
}

/// FPGA byte offsets for one VIL TW burst. Planner only.
pub fn vil_tw_register_offsets() -> [u32; VIL_TW_WORDS] {
    let mut out = [TW_CONT_OFFSET; VIL_TW_WORDS];
    out[0] = TW_FIRST_OFFSET;
    out
}

pub fn admit_vil_tw_burst_length(n: usize) -> Result<(), S9SeWorkError> {
    if n != VIL_TW_WORDS {
        return Err(S9SeWorkError::WrongBurstLength { observed: n });
    }
    Ok(())
}

/// Reporter's 12-word `send_job` is recorded, not adopted.
pub fn refuse_12_word_send_job_as_ssot(n: usize) -> Result<(), S9SeWorkError> {
    if n == 12 {
        return Err(S9SeWorkError::TwelveWordSendJobIsNotSsot);
    }
    admit_vil_tw_burst_length(n)
}

/// `send_job` type `0x52` is the FPGA job path. It does not change the
/// 13-word VIL TW SSOT and is not a mining admit.
pub fn admit_send_job_type_is_not_tw_length(job_type: u8) -> bool {
    job_type == SEND_JOB_TYPE
}

/// No am1-s9se executor. Work TX stays refused.
pub fn refuse_s9se_work_dispatch() -> Result<(), S9SeWorkError> {
    Err(S9SeWorkError::WorkDispatchRefused)
}

/// DHASH `0x8100` is a stock mode bit, not a mining admit.
pub fn dhash_raw_tw_is_not_mining_admit() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vil_tw_is_one_0x40_then_twelve_0x44() {
        let offs = vil_tw_register_offsets();
        assert_eq!(offs.len(), 13);
        assert_eq!(offs[0], 0x40);
        assert!(offs[1..].iter().all(|o| *o == 0x44));
        admit_vil_tw_burst_length(13).unwrap();
    }

    #[test]
    fn twelve_word_send_job_is_not_ssot() {
        assert_eq!(
            refuse_12_word_send_job_as_ssot(12),
            Err(S9SeWorkError::TwelveWordSendJobIsNotSsot)
        );
        refuse_12_word_send_job_as_ssot(13).unwrap();
    }

    #[test]
    fn work_dispatch_stays_refused() {
        assert_eq!(
            refuse_s9se_work_dispatch(),
            Err(S9SeWorkError::WorkDispatchRefused)
        );
        assert!(dhash_raw_tw_is_not_mining_admit());
        assert_eq!(DHASH_MODE_RAW_TW, 0x8100);
        assert_eq!(DHASH_OFFSET, 0x100);
        assert!(admit_send_job_type_is_not_tw_length(0x52));
        assert!(!admit_send_job_type_is_not_tw_length(13));
    }
}
