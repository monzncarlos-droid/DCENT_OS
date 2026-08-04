//! Pure (no-HAL) helpers for dsPIC heartbeat targeting and PIC temperature
//! publication maps.
//!
//! Context (am2 `a lab unit` standalone — swarm `wf_7b37bed4` adversarial verify,
//! 2026-05-29): the `DCENT_AM2_HEARTBEAT_ALL_ACTIVE_PICS` path originally built
//! its "extras" set from a chain-bitmask enumeration
//! (`active_dspic_addrs(0b111)` => `[0x20, 0x21, 0x22]`). On `a lab unit` the middle
//! slot (dsPIC `0x21`) is PHYSICALLY ABSENT — only slots 1+3 are populated — so
//! heartbeating `0x21` NACKs every tick, which trips the I2C service's
//! recover-and-reopen of the shared `/dev/i2c-0` fd roughly once per second and
//! destabilises the bus right when the chain is trying to enumerate.
//!
//! The correct keepalive target beyond `selected` is the EFFECTIVE chain dsPIC
//! only (the controller the chain UART actually routes to — `0x22` on the
//! slot-3 path), never a blanket bitmask that can name an empty slot. This pure
//! fn encodes that rule and is pinned by host tests so a future refactor cannot
//! silently re-introduce the absent-slot heartbeat.
//!
//! Separate contract (continuous offline audit 2026-07-22): the standard mining
//! path must retain the PIC address→chain-index map for board-temp publication
//! **before** `std::mem::take` moves `self.chains` into the work dispatcher.
//! Building the map from the emptied field yields an empty map and silently
//! drops multi-chain temperature attribution. [`build_pic_temp_chain_map`] is
//! the pure builder; production order is pinned by a structural host test.

use std::collections::HashMap;

/// Return the EXTRA dsPIC addresses to heartbeat in addition to `selected`
/// (which the caller always heartbeats on its own).
///
/// Returns at most one address: the `effective` chain dsPIC, and only when it
/// is present (`Some`) and distinct from `selected`. An absent middle slot can
/// therefore never be heartbeated — that is the whole point. When the caller's
/// `DCENT_AM2_HEARTBEAT_ALL_ACTIVE_PICS` gate is unset it passes nothing through
/// here (so only `selected` is heartbeated — byte-for-byte the proven-fleet /
///  bosminer-handoff behaviour).
pub fn heartbeat_extra_addrs(selected: u8, effective: Option<u8>) -> Vec<u8> {
    match effective {
        Some(eff) if eff != selected => vec![eff],
        _ => Vec::new(),
    }
}

/// Build the PIC I²C address → chain-index map used when the heartbeat path
/// publishes dsPIC board temperatures onto per-chain telemetry slots.
///
/// Inputs are the ordered optional PIC addresses still owned by daemon chain
/// topology (one entry per chain index). Callers must feed this **before**
/// chain ownership is moved into the work dispatcher; feeding a post-move empty
/// collection correctly fail-closes to an empty map (no invented addresses).
///
/// Duplicate addresses keep the last index (same as `HashMap::collect` from
/// the prior inline construction).
pub fn build_pic_temp_chain_map(
    pic_addresses_by_chain_index: impl IntoIterator<Item = Option<u8>>,
) -> HashMap<u8, usize> {
    pic_addresses_by_chain_index
        .into_iter()
        .enumerate()
        .filter_map(|(idx, addr)| addr.map(|a| (a, idx)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot25_topology_targets_effective_only_never_absent_middle() {
        // `a lab unit`: selected = 0x20 (slot 1), effective chain dsPIC = 0x22
        // (slot 3); the middle slot 0x21 is physically absent.
        let extras = heartbeat_extra_addrs(0x20, Some(0x22));
        assert_eq!(extras, vec![0x22]);
        // The regression this pins: 0x21 must NEVER be a heartbeat target,
        // because NACKing it tears down + reopens the shared i2c-0 fd each tick.
        assert!(!extras.contains(&0x21));
    }

    #[test]
    fn effective_equal_selected_yields_no_extras() {
        // The effective chain dsPIC IS the selected one → nothing extra.
        assert_eq!(heartbeat_extra_addrs(0x20, Some(0x20)), Vec::<u8>::new());
    }

    #[test]
    fn no_effective_yields_no_extras() {
        assert_eq!(heartbeat_extra_addrs(0x20, None), Vec::<u8>::new());
    }

    #[test]
    fn single_hashboard_unit_only_selected() {
        // A single-chain unit routes the chain UART to its only dsPIC, so
        // effective == selected and no extra keepalive target is produced.
        assert_eq!(heartbeat_extra_addrs(0x22, Some(0x22)), Vec::<u8>::new());
    }

    #[test]
    fn multi_chain_topology_maps_each_pic_address_to_chain_index() {
        // S9/PIC1704-class: three chains, one PIC each (0x55/0x56/0x57).
        let map = build_pic_temp_chain_map([Some(0x55), Some(0x56), Some(0x57)]);
        assert_eq!(map.len(), 3);
        assert_eq!(map.get(&0x55), Some(&0));
        assert_eq!(map.get(&0x56), Some(&1));
        assert_eq!(map.get(&0x57), Some(&2));
    }

    #[test]
    fn multi_chain_with_sparse_pic_addresses_skips_none_without_inventing() {
        // AM2-style: middle slot empty (None) — map must not invent 0x21.
        let map = build_pic_temp_chain_map([Some(0x20), None, Some(0x22)]);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&0x20), Some(&0));
        assert_eq!(map.get(&0x22), Some(&2));
        assert!(!map.contains_key(&0x21));
    }

    #[test]
    fn empty_topology_fail_closes_to_empty_map() {
        let map = build_pic_temp_chain_map(std::iter::empty::<Option<u8>>());
        assert!(map.is_empty());
        // Post-move empty source (the historical bug): same fail-closed result.
        let post_move_empty: Vec<Option<u8>> = Vec::new();
        let from_emptied = build_pic_temp_chain_map(post_move_empty);
        assert!(from_emptied.is_empty());
    }

    #[test]
    fn all_none_topology_fail_closes_to_empty_map() {
        let map = build_pic_temp_chain_map([None, None, None]);
        assert!(map.is_empty());
    }

    /// Production standard-mining path must retain the map via the pure helper
    /// **before** `std::mem::take` moves chains into the work dispatcher.
    /// Rebuilding from the emptied `self.chains` after the take is the
    /// continuous-audit NO-SHIP residual this pins closed.
    #[test]
    fn production_daemon_builds_pic_temp_chain_map_before_dispatch_chains_move() {
        let daemon = include_str!("../../dcentrald/src/daemon.rs");
        let helper = "build_pic_temp_chain_map";
        let take_marker = "std::mem::take(&mut self.chains)";

        let helper_pos = daemon
            .find(helper)
            .expect("daemon must call build_pic_temp_chain_map");
        let take_pos = daemon
            .find(take_marker)
            .expect("daemon must still move chains into the dispatcher via mem::take");
        assert!(
            helper_pos < take_pos,
            "pic temp chain map must be built from live topology before mem::take empties self.chains"
        );

        // Heartbeat publisher must consume the retained map, not rebuild from
        // emptied self.chains after the take (old bug pattern).
        let after_take = &daemon[take_pos..];
        assert!(
            !after_take.contains("chain.pic_address.map(|addr| (addr, idx))"),
            "must not rebuild hb_pic_chain_map from self.chains after mem::take"
        );
        assert!(
            after_take.contains("hb_pic_chain_map"),
            "retained hb_pic_chain_map must still be used on the heartbeat path"
        );
        assert!(
            daemon.contains("dcentrald_common::dspic_heartbeat::build_pic_temp_chain_map")
                || daemon.contains("build_pic_temp_chain_map("),
            "production must call the shipped pure helper, not a one-off copy"
        );
    }
}
