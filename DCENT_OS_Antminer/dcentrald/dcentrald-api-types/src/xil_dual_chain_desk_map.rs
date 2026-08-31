//! XIL dual-chain desk map (ttyS1 + ttyS3) — RE-4A host-testable bookkeeping.
//!
//! Pins independent CMD endpoints for the AM2/XIL dual-chain geometry without
//! opening live UART, energizing rails, or claiming multi-SKU dual-chain mining.
//! Each planned chain owns its own slot identity and GetAddress admission
//! evidence. Work-ledger foreign-commit refuse is covered by
//! `dcentrald::work_ledger` (Linux/CI); this module pins the desk map keys that
//! ledger must use so traffic cannot cross-correlate.

use crate::bm1398_get_address::{
    admit_nbp1901_bm1398_get_address_window, locked_bm1398_unassigned_get_address_body,
    Nbp1901Bm1398GetAddressAdmission,
};

/// One desk-only XIL CMD endpoint (no live serial open).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XilDeskChainEndpoint {
    pub serial_device: &'static str,
    pub am2_slot: u8,
    pub dspic_addr: u8,
    /// Sequential chain / work-ledger key (0..=N-1).
    pub chain_id: u8,
    /// Canonical PL UART MMIO base for this slot (documentation pin).
    pub cmd_mmio_base: u32,
}

/// Canonical `a lab unit`-class dual-chain desk map: ttyS1 (slot 0) + ttyS3 (slot 2).
pub const XIL_DUAL_CHAIN_DESK_MAP: [XilDeskChainEndpoint; 2] = [
    XilDeskChainEndpoint {
        serial_device: "/dev/ttyS1",
        am2_slot: 0,
        dspic_addr: 0x20,
        chain_id: 0,
        cmd_mmio_base: 0x4100_1000,
    },
    XilDeskChainEndpoint {
        serial_device: "/dev/ttyS3",
        am2_slot: 2,
        dspic_addr: 0x22,
        chain_id: 1,
        cmd_mmio_base: 0x4102_1000,
    },
];

/// Per-chain sealed GetAddress admissions for desk isolation tests.
pub fn admit_independent_nbp1901_windows() -> [Nbp1901Bm1398GetAddressAdmission; 2] {
    let body = locked_bm1398_unassigned_get_address_body();
    let mk = || {
        let responses = vec![body; 114];
        admit_nbp1901_bm1398_get_address_window(responses.iter().map(|b| &b[..]))
            .expect("desk synthetic 114-frame BM1398 window must admit")
    };
    [mk(), mk()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_common::am2_topology::{dspic_address_for_slot, slot_for_uart, uart_for_slot};

    #[test]
    fn desk_map_pins_independent_ttys1_and_ttys3_cmd_endpoints() {
        assert_eq!(XIL_DUAL_CHAIN_DESK_MAP[0].serial_device, "/dev/ttyS1");
        assert_eq!(XIL_DUAL_CHAIN_DESK_MAP[1].serial_device, "/dev/ttyS3");
        assert_ne!(
            XIL_DUAL_CHAIN_DESK_MAP[0].cmd_mmio_base,
            XIL_DUAL_CHAIN_DESK_MAP[1].cmd_mmio_base
        );
        assert_eq!(XIL_DUAL_CHAIN_DESK_MAP[0].cmd_mmio_base, 0x4100_1000);
        assert_eq!(XIL_DUAL_CHAIN_DESK_MAP[1].cmd_mmio_base, 0x4102_1000);

        for ep in &XIL_DUAL_CHAIN_DESK_MAP {
            assert_eq!(slot_for_uart(ep.serial_device), Some(ep.am2_slot));
            assert_eq!(uart_for_slot(ep.am2_slot), Some(ep.serial_device));
            assert_eq!(dspic_address_for_slot(ep.am2_slot), Some(ep.dspic_addr));
        }
        assert_ne!(
            XIL_DUAL_CHAIN_DESK_MAP[0].am2_slot,
            XIL_DUAL_CHAIN_DESK_MAP[1].am2_slot
        );
        assert_ne!(
            XIL_DUAL_CHAIN_DESK_MAP[0].dspic_addr,
            XIL_DUAL_CHAIN_DESK_MAP[1].dspic_addr
        );
        assert_ne!(
            XIL_DUAL_CHAIN_DESK_MAP[0].chain_id,
            XIL_DUAL_CHAIN_DESK_MAP[1].chain_id
        );
    }

    #[test]
    fn per_chain_get_address_admissions_are_independent_move_only_seals() {
        let [a, b] = admit_independent_nbp1901_windows();
        assert_eq!(a.observed_frames().get(), 114);
        assert_eq!(b.observed_frames().get(), 114);
        assert_eq!(a.chip_id(), 0x1398);
        assert_eq!(b.chip_id(), 0x1398);
        drop(a);
        assert_eq!(b.expected_chip_count(), 114);
    }

    #[test]
    fn get_address_population_on_one_endpoint_does_not_authorize_the_peer() {
        let body = locked_bm1398_unassigned_get_address_body();
        let only_left = vec![body; 114];
        let left = admit_nbp1901_bm1398_get_address_window(only_left.iter().map(|b| &b[..]))
            .expect("ttyS1 window");
        assert_eq!(left.observed_frames().get(), 114);

        assert!(admit_nbp1901_bm1398_get_address_window(std::iter::empty::<&[u8]>()).is_err());
        let partial = vec![body; 76];
        assert!(
            admit_nbp1901_bm1398_get_address_window(partial.iter().map(|b| &b[..])).is_err(),
            "ttyS3 must not inherit ttyS1 population"
        );
    }

    #[test]
    fn work_ledger_keys_are_per_endpoint_and_not_shared() {
        // Desk contract for ChainWorkLedger wiring: each CMD endpoint's
        // chain_id is the ledger_key. Same logical work_id on two chains must
        // never share a table (enforced by distinct keys + foreign-commit refuse).
        let keys: Vec<u8> = XIL_DUAL_CHAIN_DESK_MAP
            .iter()
            .map(|ep| ep.chain_id)
            .collect();
        assert_eq!(keys, vec![0, 1]);
        assert_eq!(
            keys.len(),
            keys.iter().collect::<std::collections::BTreeSet<_>>().len()
        );
    }
}
