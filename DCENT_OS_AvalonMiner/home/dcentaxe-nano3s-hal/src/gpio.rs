// SPDX-License-Identifier: GPL-3.0-or-later
//
// sysfs GPIO read access for K230 Linux. Stub for Phase 1 scaffold —
// the real Nano 3S pinout (LED, recovery button, USB-C signaling) needs to
// come from a teardown or FCC photos pass before any pin gets wired. See
//  §3 for the gap.

use crate::HalError;

/// Probe whether a given sysfs GPIO line is exported and readable.
/// Phase 1: returns `Ok(false)` on every host that's not K230 + sysfs-GPIO-enabled.
pub fn line_present(line: u32) -> Result<bool, HalError> {
    let path = format!("/sys/class/gpio/gpio{line}/value");
    Ok(std::path::Path::new(&path).exists())
}
