//! Canonical pure share-pipeline entry points (ADR-0009 mining strangler).
//!
//! Mining engines (`WorkDispatcher`, hybrid serial loops, `serial_mining`,
//! `am3_bb_mining`, and future ESP pure-core adapters) should call **these**
//! helpers for header validation and midstate construction rather than
//! re-implementing double-SHA / target compare locally.
//!
//! # Boundaries
//!
//! | Concern | Lives here? | Location |
//! |---------|-------------|----------|
//! | Midstate / coinbase / merkle | Yes | [`WorkBuilder`], [`compute_midstate_from_prefix`] |
//! | Share vs target | Yes | [`validate_share`], [`validate_full_header`] |
//! | BIP320 version reconstruct | No (ASIC-side) | `dcentrald_asic::bm1362` bip320 helpers |
//! | Dedup key policy | Not yet unified | Per-engine today — future extraction |
//! | Pool submit I/O | No | V1/V2 clients |
//!
//! # Decade rule
//!
//! If you add a third copy of “assemble header + hash + compare target” in a
//! mining path, stop and extend this module (or a future `dcent-stratum-core`)
//! instead.
//!
//! # Call sites (cycle-2 migration)
//!
//! Prefer `dcentrald_stratum::share_pipeline::{WorkBuilder, validate_full_header,
//! validate_share, MiningWork}` from:
//! `work_dispatcher`, `serial_mining`, `s19j_hybrid_mining`, `am3_bb_mining`,
//! `stock_mining`, `s19j_tap_mining`, `sim_runtime`.

pub use crate::work::{
    compute_midstate_from_prefix, double_sha256, sha256_compress, validate_full_header,
    validate_share, MiningWork, WorkBuilder,
};

/// Serial-path share dedup key (ASIC job id + nonce + version bits).
///
/// Re-exported from `dcentrald_common::serial_work_policy` so mining engines
/// have **one** import surface for share math (validate + dedup policy) without
/// inventing parallel key tuples.
pub use dcentrald_common::{
    generation_share_dedup_key, serial_share_dedup_key, should_clear_seen_shares,
    DEFAULT_SEEN_SHARES_CAP, GENERATION_SEEN_RETAIN_WINDOW, GENERATION_SEEN_SOFT_CAP_DISPATCHER,
    GENERATION_SEEN_SOFT_CAP_SERIAL,
};

/// FPGA / multi-midstate share dedup key (generation + nonce + midstate index).
///
/// Thin alias of [`generation_share_dedup_key`] for WorkDispatcher-class paths.
/// When midstates are not distinct, pass `midstate_idx = 0` for all nonces so
/// the key collapses to generation+nonce uniqueness.
#[inline]
pub fn dispatcher_share_dedup_key(generation: u64, nonce: u32, midstate_idx: u8) -> (u64, u32, u8) {
    generation_share_dedup_key(generation, nonce, midstate_idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_pipeline_reexports_are_callable() {
        // Smoke: the public surface stays linked for engine call sites.
        let _ = std::mem::size_of::<WorkBuilder>();
        let easiest = [0xffu8; 32];
        let header = [0u8; 80];
        // Zero header hash is not all-zero difficulty-1 guarantee on all
        // targets; easiest target all-0xff accepts any hash.
        assert!(validate_full_header(&header, &easiest));
        let _ = double_sha256(&[0u8; 1]);
        let iv = [0u32; 8];
        let block = [0u8; 64];
        let _ = sha256_compress(&iv, &block);
    }

    #[test]
    fn serial_and_dispatcher_dedup_keys_are_stable() {
        assert_eq!(
            serial_share_dedup_key(8, 0xdead_beef, 0x1ff),
            (8, 0xdead_beef, 0x1ff)
        );
        assert_eq!(dispatcher_share_dedup_key(42, 0x11, 3), (42, 0x11, 3));
        // Distinct midstate indices must not collide under the same generation.
        assert_ne!(
            dispatcher_share_dedup_key(1, 0xaa, 0),
            dispatcher_share_dedup_key(1, 0xaa, 1)
        );
    }
}
