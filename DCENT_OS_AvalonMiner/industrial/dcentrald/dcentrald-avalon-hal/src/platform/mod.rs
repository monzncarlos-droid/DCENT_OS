// SPDX-License-Identifier: GPL-3.0-or-later
//
// `Platform` trait + per-board impls. Phase 1 scaffold.
//
// Mirrors dcentos/dcentrald/dcentrald-hal/src/platform/mod.rs in spirit —
// runtime trait dispatch, no Cargo features, one binary for multiple SoCs.

use crate::HalError;

pub mod k210;
pub mod k230;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardType {
    K230Industrial,
    K210Industrial,
    Unsupported,
}

/// Common HAL surface across all industrial Avalon platforms.
///
/// Phase 1: minimal — just identification. Adds chain_access, fan_access,
/// gpio_access, telemetry in next plan once we have live-unit probing.
pub trait Platform: Send + Sync {
    fn board_type(&self) -> BoardType;
    fn description(&self) -> &'static str;
}

/// Detect and return a boxed `Platform` impl. Errors on unsupported hosts.
pub fn detect_platform() -> Result<Box<dyn Platform>, HalError> {
    #[cfg(target_arch = "riscv64")]
    {
        if std::fs::read_to_string("/proc/device-tree/model")
            .map(|s| s.to_lowercase().contains("k230"))
            .unwrap_or(false)
        {
            return Ok(Box::new(k230::K230Industrial::new()));
        }
    }
    Err(HalError::UnsupportedPlatform)
}
