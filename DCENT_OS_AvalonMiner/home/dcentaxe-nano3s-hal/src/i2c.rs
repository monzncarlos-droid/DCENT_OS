// SPDX-License-Identifier: GPL-3.0-or-later
//
// /dev/i2c-* wrapper for K230 Linux. Stub for Phase 1 scaffold.
// §3, the Nano 3S
// PMIC, NTC thermistor placement, and EEPROM (if any) are all unconfirmed
// pending teardown / FCC photos. Real implementation lands in next plan.

use crate::HalError;

/// Returns the list of `/dev/i2c-N` devices available on the host.
pub fn list_buses() -> Result<Vec<String>, HalError> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir("/dev") {
        Ok(d) => d,
        Err(_) => return Ok(out),
    };
    for e in entries.flatten() {
        if let Some(name) = e.file_name().to_str() {
            if name.starts_with("i2c-") {
                out.push(format!("/dev/{}", name));
            }
        }
    }
    Ok(out)
}
