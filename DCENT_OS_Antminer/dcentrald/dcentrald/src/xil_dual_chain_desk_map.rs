//! XIL dual-chain desk map integration tests (work-ledger isolation).
//!
//! Topology + sealed GetAddress pins live in
//! `dcentrald_api_types::xil_dual_chain_desk_map` (host-testable). This module
//! additionally proves `ChainWorkLedger` refuses cross-chain correlation for
//! the ttyS1/ttyS3 desk map (Linux/CI; requires HAL-linked daemon crate).

use dcentrald_api_types::xil_dual_chain_desk_map::{
    admit_independent_nbp1901_windows, XIL_DUAL_CHAIN_DESK_MAP,
};

use crate::am2_chain_plan::build_am2_chain_plan;
use crate::work_ledger::{ChainWorkLedger, LedgerCommitError, LedgerLookup};

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const GUARD: Duration = Duration::from_secs(5);

    #[test]
    fn am2_chain_plan_matches_api_types_desk_map() {
        let devices = XIL_DUAL_CHAIN_DESK_MAP
            .iter()
            .map(|ep| ep.serial_device.to_string())
            .collect::<Vec<_>>();
        let plan = build_am2_chain_plan(&devices).unwrap();
        assert_eq!(plan.len(), 2);
        for (ctx, ep) in plan.iter().zip(XIL_DUAL_CHAIN_DESK_MAP.iter()) {
            assert_eq!(ctx.serial_device, ep.serial_device);
            assert_eq!(ctx.am2_slot, ep.am2_slot);
            assert_eq!(ctx.dspic_addr, ep.dspic_addr);
            assert_eq!(ctx.chain_id, ep.chain_id);
        }
    }

    #[test]
    fn work_ledgers_refuse_cross_chain_correlation_on_dual_map() {
        let now = Instant::now();
        let mut ledgers = XIL_DUAL_CHAIN_DESK_MAP
            .iter()
            .map(|ep| ChainWorkLedger::new(256, usize::from(ep.chain_id)).unwrap())
            .collect::<Vec<_>>();

        let left_res = ledgers[0].reserve(10, now, GUARD).unwrap();
        let right_res = ledgers[1].reserve(11, now, GUARD).unwrap();
        assert_eq!(left_res.work_id(), 0);
        assert_eq!(right_res.work_id(), 0);

        ledgers[0].commit(left_res, "ttyS1-work").unwrap();
        let stolen = ledgers[0].reserve(12, now, GUARD).unwrap();
        assert!(matches!(
            ledgers[1].commit(stolen, "laundered"),
            Err(LedgerCommitError::ForeignReservation {
                expected: 1,
                observed: 0
            })
        ));
        ledgers[1].commit(right_res, "ttyS3-work").unwrap();

        match ledgers[0].lookup(0) {
            LedgerLookup::Found(record) => assert_eq!(record.payload, "ttyS1-work"),
            _ => panic!("ttyS1 ledger lost its record"),
        }
        match ledgers[1].lookup(0) {
            LedgerLookup::Found(record) => assert_eq!(record.payload, "ttyS3-work"),
            _ => panic!("ttyS3 ledger lost its record"),
        }
    }

    #[test]
    fn independent_get_address_seals_match_desk_map_arity() {
        let [a, b] = admit_independent_nbp1901_windows();
        assert_eq!(a.observed_frames().get(), 114);
        assert_eq!(b.observed_frames().get(), 114);
        assert_eq!(XIL_DUAL_CHAIN_DESK_MAP.len(), 2);
    }
}