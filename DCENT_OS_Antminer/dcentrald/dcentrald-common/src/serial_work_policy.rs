//! Shared serial-mining work-slot / share-dedup policy (ADR-0009 strangler).
//!
//! Hybrid, serial_mining, and am3_bb historically copied magic numbers
//! (history depth 32, job-id step 8, seen-share cap 8192). Keep **one** pure
//! definition here; engines should import these constants rather than
//! re-declaring them.
//!
//! Status: constants + pure helpers only. Migrating hybrid/serial loops to
//! call these is behavior-preserving (same numbers).

/// Default work history ring depth per ASIC job-id (hybrid serial path).
pub const DEFAULT_WORK_HISTORY_PER_ID: usize = 32;

/// BM1398-class paths sometimes keep a deeper history (serial_mining).
pub const BM1398_WORK_HISTORY_PER_ID: usize = 96;

/// AM3-BB local history depth (historical port value).
pub const AM3_BB_WORK_HISTORY_PER_ID: usize = 128;

/// ASIC job-id stride used on AM2 serial dispatch (skips midstate slots).
pub const DEFAULT_SERIAL_JOB_ID_STEP: u8 = 8;

/// Clear seen-share set when it exceeds this size (hybrid path).
pub const DEFAULT_SEEN_SHARES_CAP: usize = 8192;

/// Soft cap for generation-keyed dedup on `serial_mining` (post-insert prune).
///
/// Distinct from [`DEFAULT_SEEN_SHARES_CAP`]: hybrid `SeenShareSet` keys by
/// (job_id, nonce, version_bits) and full-clears; generation-keyed paths keep
/// recent dispatch generations so in-flight nonces are not re-admitted as new.
pub const GENERATION_SEEN_SOFT_CAP_SERIAL: usize = 4096;

/// Soft cap for generation-keyed dedup on FPGA `work_dispatcher` (historical 4000).
pub const GENERATION_SEEN_SOFT_CAP_DISPATCHER: usize = 4000;

/// Keep entries with `generation >= current.saturating_sub(this)` when pruning.
pub const GENERATION_SEEN_RETAIN_WINDOW: u64 = 2048;

/// Serial BM1362-class nonce frame length (bytes).
pub const BM1362_SERIAL_NONCE_LEN: usize = 11;

/// Advance ASIC job id with wrapping add (same as hybrid/serial today).
pub fn next_asic_job_id(current: u8, step: u8) -> u8 {
    current.wrapping_add(step)
}

/// Canonical share-dedup key used on serial AM2-class paths.
pub fn serial_share_dedup_key(asic_job_id: u8, nonce: u32, version_bits: u16) -> (u8, u32, u16) {
    (asic_job_id, nonce, version_bits)
}

/// Generation-scoped dedup key (serial_mining / work_dispatcher).
///
/// `midstate_idx` is collapsed to 0 by callers when midstates are not distinct
/// (inactive version rolling), so identical nonces across slots collapse.
pub fn generation_share_dedup_key(generation: u64, nonce: u32, midstate_idx: u8) -> (u64, u32, u8) {
    (generation, nonce, midstate_idx)
}

/// Generation cutoff for retain-based prune (avoids wholesale clear).
pub fn generation_dedup_cutoff(current_generation: u64, retain_window: u64) -> u64 {
    current_generation.saturating_sub(retain_window)
}

/// Whether the seen-share set should be cleared to bound memory.
pub fn should_clear_seen_shares(current_len: usize, cap: usize) -> bool {
    current_len > cap
}

/// Whether a generation-keyed set should prune old generations (same boundary
/// as [`should_clear_seen_shares`], named for the generation-keyed call sites).
pub fn should_prune_generation_seen(current_len: usize, soft_cap: usize) -> bool {
    should_clear_seen_shares(current_len, soft_cap)
}

/// Select work-history depth for a chip family id when known.
pub fn work_history_depth_for_chip_id(chip_id: u16) -> usize {
    match chip_id {
        0x1398 => BM1398_WORK_HISTORY_PER_ID,
        _ => DEFAULT_WORK_HISTORY_PER_ID,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_id_step_matches_hybrid_constant() {
        assert_eq!(DEFAULT_SERIAL_JOB_ID_STEP, 8);
        assert_eq!(next_asic_job_id(0xF8, 8), 0x00);
        assert_eq!(next_asic_job_id(0, 8), 8);
    }

    #[test]
    fn seen_share_cap_clear_boundary() {
        assert!(!should_clear_seen_shares(8192, DEFAULT_SEEN_SHARES_CAP));
        assert!(should_clear_seen_shares(8193, DEFAULT_SEEN_SHARES_CAP));
    }

    #[test]
    fn history_depths_are_stable() {
        assert_eq!(work_history_depth_for_chip_id(0x1362), 32);
        assert_eq!(work_history_depth_for_chip_id(0x1398), 96);
        assert_eq!(DEFAULT_WORK_HISTORY_PER_ID, 32);
    }

    #[test]
    fn dedup_key_is_tuple_identity() {
        assert_eq!(
            serial_share_dedup_key(8, 0xdead_beef, 0x1ff),
            (8, 0xdead_beef, 0x1ff)
        );
    }

    #[test]
    fn generation_dedup_key_and_cutoff_are_stable() {
        assert_eq!(
            generation_share_dedup_key(100, 0xdead_beef, 3),
            (100, 0xdead_beef, 3)
        );
        assert_eq!(
            generation_dedup_cutoff(3000, GENERATION_SEEN_RETAIN_WINDOW),
            952
        );
        assert_eq!(
            generation_dedup_cutoff(100, GENERATION_SEEN_RETAIN_WINDOW),
            0
        );
        assert_eq!(GENERATION_SEEN_SOFT_CAP_SERIAL, 4096);
        assert_eq!(GENERATION_SEEN_SOFT_CAP_DISPATCHER, 4000);
        assert_eq!(GENERATION_SEEN_RETAIN_WINDOW, 2048);
        assert!(should_prune_generation_seen(
            4097,
            GENERATION_SEEN_SOFT_CAP_SERIAL
        ));
        assert!(!should_prune_generation_seen(
            4096,
            GENERATION_SEEN_SOFT_CAP_SERIAL
        ));
    }
}
