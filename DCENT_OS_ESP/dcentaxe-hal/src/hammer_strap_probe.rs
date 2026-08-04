// SPDX-License-Identifier: GPL-3.0-or-later
//! ESP-IDF seam for the read-only Hammer DC identity-strap probe.

use log::info;

use crate::hammer_strap::{
    classify_hammer_strap_probe, hammer_strap_addr_bit, HammerStrapProbeVerdict, HAMMER_STRAP_ADDRS,
};
use crate::i2c::I2cBus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HammerStrapProbeResult {
    pub expected_addr: u8,
    pub observed_mask: u8,
    pub verdict: HammerStrapProbeVerdict,
}

/// Probe the Hammer DC identity strap with address-only, zero-byte I2C writes.
///
/// Caller contract: invoke only after the config layer has model-gated the
/// board as `model.is_hammer_dc()`. Addresses in this set are not globally
/// unique (0x48 and 0x4C are used by unrelated BitAxe peripherals).
pub fn probe_hammer_identity_strap(i2c: &mut I2cBus, expected_addr: u8) -> HammerStrapProbeResult {
    let mut observed_mask = 0u8;
    for addr in HAMMER_STRAP_ADDRS {
        if i2c.probe(addr) {
            observed_mask |= hammer_strap_addr_bit(addr);
        }
    }
    let verdict = classify_hammer_strap_probe(expected_addr, observed_mask);
    info!(
        "Hammer DC identity-strap probe (read-only): expected=0x{:02X} mask=0x{:02X} -> {:?}",
        expected_addr, observed_mask, verdict
    );
    HammerStrapProbeResult {
        expected_addr,
        observed_mask,
        verdict,
    }
}
