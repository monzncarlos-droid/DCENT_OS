//! Desk-only XIL dual-chain CMD slot map (RE-4A missing-SKU bring-up).
//!
//! Codifies that desk dual-chain work for missing SKUs uses **independent**
//! CMD endpoints `/dev/ttyS1` and `/dev/ttyS3`. Each chain owns its own AM2
//! slot, dsPIC address, and ledger identity. Presence, reset disposition,
//! GetAddress windows, and work ledgers must not cross-correlate.
//!
//! Pure data + host-testable checks. No UART I/O. No energize. Prefer proving
//! BM1362 dual-chain bookkeeping on XIL before claiming multi-SKU dual-chain.

use crate::am2_topology::{dspic_address_for_slot, slot_for_uart};

/// One independent desk chain on the XIL PL-UART fabric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XilDualChainDeskSlot {
    /// Independent CMD endpoint (`/dev/ttyS1` or `/dev/ttyS3`).
    pub cmd_endpoint: &'static str,
    /// AM2 hashboard slot (PL UART index).
    pub am2_slot: u8,
    /// Slot-owned dsPIC I²C address.
    pub dspic_addr: u8,
    /// Distinct ledger identity for presence / reset / GetAddress / work.
    pub ledger_id: u8,
}

/// Canonical desk dual-chain map for missing-SKU XIL bring-up.
///
/// Slot 0 → `/dev/ttyS1` @ dsPIC `0x20`; slot 2 → `/dev/ttyS3` @ dsPIC `0x22`.
/// These are independent CMD endpoints — population counted on one UART is
/// never proof the companion UART is owned.
pub const XIL_MISSING_SKU_DUAL_CHAIN_DESK_MAP: [XilDualChainDeskSlot; 2] = [
    XilDualChainDeskSlot {
        cmd_endpoint: "/dev/ttyS1",
        am2_slot: 0,
        dspic_addr: 0x20,
        ledger_id: 0,
    },
    XilDualChainDeskSlot {
        cmd_endpoint: "/dev/ttyS3",
        am2_slot: 2,
        dspic_addr: 0x22,
        ledger_id: 1,
    },
];

/// True when two desk slots share no CMD endpoint, slot, PIC, or ledger id.
pub fn desk_slots_are_independent(a: &XilDualChainDeskSlot, b: &XilDualChainDeskSlot) -> bool {
    a.cmd_endpoint != b.cmd_endpoint
        && a.am2_slot != b.am2_slot
        && a.dspic_addr != b.dspic_addr
        && a.ledger_id != b.ledger_id
}

/// Per-chain desk ledger. Observation-only; not a hardware receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XilDeskChainLedger {
    slot: XilDualChainDeskSlot,
    presence: bool,
    reset_generation: u32,
    get_address_frames: u16,
    work_submitted: u64,
}

impl XilDeskChainLedger {
    pub const fn new(slot: XilDualChainDeskSlot) -> Self {
        Self {
            slot,
            presence: false,
            reset_generation: 0,
            get_address_frames: 0,
            work_submitted: 0,
        }
    }

    pub const fn slot(&self) -> XilDualChainDeskSlot {
        self.slot
    }

    pub const fn presence(&self) -> bool {
        self.presence
    }

    pub const fn reset_generation(&self) -> u32 {
        self.reset_generation
    }

    pub const fn get_address_frames(&self) -> u16 {
        self.get_address_frames
    }

    pub const fn work_submitted(&self) -> u64 {
        self.work_submitted
    }

    pub fn record_presence(&mut self, present: bool) {
        self.presence = present;
    }

    pub fn bump_reset_generation(&mut self) {
        self.reset_generation = self.reset_generation.saturating_add(1);
    }

    pub fn record_get_address_frames(&mut self, frames: u16) {
        self.get_address_frames = frames;
    }

    pub fn record_work_submitted(&mut self, count: u64) {
        self.work_submitted = self.work_submitted.saturating_add(count);
    }
}

/// Why desk ledgers cannot be merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XilDeskLedgerMergeError {
    /// Presence / reset / GetAddress / work ledgers must stay per-chain.
    CrossCorrelateForbidden,
}

impl core::fmt::Display for XilDeskLedgerMergeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CrossCorrelateForbidden => write!(
                f,
                "XIL dual-chain desk ledgers must not cross-correlate \
                 (presence/reset/GetAddress/work are per-CMD-endpoint)"
            ),
        }
    }
}

/// Fail-closed merge: dual-chain desk ledgers are never combinable.
pub fn merge_desk_chain_ledgers(
    _a: &XilDeskChainLedger,
    _b: &XilDeskChainLedger,
) -> Result<XilDeskChainLedger, XilDeskLedgerMergeError> {
    Err(XilDeskLedgerMergeError::CrossCorrelateForbidden)
}

/// Validate the static desk map against the AM2 topology leaf.
pub fn validate_xil_missing_sku_dual_chain_desk_map() -> Result<(), &'static str> {
    let [a, b] = XIL_MISSING_SKU_DUAL_CHAIN_DESK_MAP;
    if a.cmd_endpoint != "/dev/ttyS1" || b.cmd_endpoint != "/dev/ttyS3" {
        return Err("desk dual-chain CMD endpoints must be /dev/ttyS1 and /dev/ttyS3");
    }
    if slot_for_uart(a.cmd_endpoint) != Some(a.am2_slot)
        || slot_for_uart(b.cmd_endpoint) != Some(b.am2_slot)
    {
        return Err("desk map AM2 slots must match am2_topology::slot_for_uart");
    }
    if dspic_address_for_slot(a.am2_slot) != Some(a.dspic_addr)
        || dspic_address_for_slot(b.am2_slot) != Some(b.dspic_addr)
    {
        return Err("desk map dsPIC addresses must match am2_topology");
    }
    if !desk_slots_are_independent(&a, &b) {
        return Err("desk dual-chain slots must be fully independent");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desk_map_pins_independent_ttys1_and_ttys3() {
        validate_xil_missing_sku_dual_chain_desk_map().expect("desk map must validate");
        let [a, b] = XIL_MISSING_SKU_DUAL_CHAIN_DESK_MAP;
        assert_eq!(a.cmd_endpoint, "/dev/ttyS1");
        assert_eq!(b.cmd_endpoint, "/dev/ttyS3");
        assert_eq!(a.am2_slot, 0);
        assert_eq!(b.am2_slot, 2);
        assert_eq!(a.dspic_addr, 0x20);
        assert_eq!(b.dspic_addr, 0x22);
        assert_eq!(a.ledger_id, 0);
        assert_eq!(b.ledger_id, 1);
        assert!(desk_slots_are_independent(&a, &b));
    }

    #[test]
    fn presence_reset_get_address_work_ledgers_do_not_cross_correlate() {
        let [slot_a, slot_b] = XIL_MISSING_SKU_DUAL_CHAIN_DESK_MAP;
        let mut ledger_a = XilDeskChainLedger::new(slot_a);
        let mut ledger_b = XilDeskChainLedger::new(slot_b);

        ledger_a.record_presence(true);
        ledger_a.bump_reset_generation();
        ledger_a.record_get_address_frames(114);
        ledger_a.record_work_submitted(10);

        // Companion chain stays cold — A's activity must not appear on B.
        assert!(!ledger_b.presence());
        assert_eq!(ledger_b.reset_generation(), 0);
        assert_eq!(ledger_b.get_address_frames(), 0);
        assert_eq!(ledger_b.work_submitted(), 0);

        ledger_b.record_presence(true);
        ledger_b.bump_reset_generation();
        ledger_b.record_get_address_frames(76);
        ledger_b.record_work_submitted(3);

        assert_eq!(ledger_a.get_address_frames(), 114);
        assert_eq!(ledger_b.get_address_frames(), 76);
        assert_eq!(ledger_a.work_submitted(), 10);
        assert_eq!(ledger_b.work_submitted(), 3);
        assert_eq!(ledger_a.reset_generation(), 1);
        assert_eq!(ledger_b.reset_generation(), 1);

        assert_eq!(
            merge_desk_chain_ledgers(&ledger_a, &ledger_b),
            Err(XilDeskLedgerMergeError::CrossCorrelateForbidden)
        );
        let msg = format!("{}", XilDeskLedgerMergeError::CrossCorrelateForbidden);
        assert!(msg.contains("must not cross-correlate"));
        assert!(msg.contains("per-CMD-endpoint"));
    }

    #[test]
    fn shared_endpoint_or_ledger_is_not_independent() {
        let [a, b] = XIL_MISSING_SKU_DUAL_CHAIN_DESK_MAP;
        let same_uart = XilDualChainDeskSlot {
            cmd_endpoint: a.cmd_endpoint,
            ..b
        };
        assert!(!desk_slots_are_independent(&a, &same_uart));

        let same_ledger = XilDualChainDeskSlot {
            ledger_id: a.ledger_id,
            ..b
        };
        assert!(!desk_slots_are_independent(&a, &same_ledger));
    }
}
