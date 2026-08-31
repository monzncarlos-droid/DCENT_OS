// SPDX-License-Identifier: GPL-3.0-or-later
//
// dcentaxe-nano3s-hal — Linux HAL for the Canaan Avalon Nano 3 / Nano 3S / Mini 3.
//
// Target: Kendryte K230 (RISC-V Xuantie C908) Linux little core.
// All hardware access uses standard Linux userspace interfaces — sysfs GPIO,
// hwmon temperature, sysfs PWM — not direct /dev/mem mmap. K230's RT-Smart big
// core owns the SPI controllers; we talk to it via SysV msgq (see
// `dcent-avalon-proto::transport`).
//
// Phase 1 scaffold — modules are stubs. Real implementations land in next plan.

pub mod gpio;
pub mod i2c;
pub mod ina226;
pub mod pwm;
pub mod temp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvalonHomeBoard {
    /// Avalon Nano 3 — 4 TH/s, 10 chips, ~7nm, no LCD.
    Nano3,
    /// Avalon Nano 3S — 6 TH/s, 12 chips, ~4nm, front-panel LCD.
    Nano3s,
    /// Avalon Mini 3 — small box, K230, larger hashboard.
    Mini3,
    /// Unknown — running on a non-Avalon K230 (CanMV dev board, etc.) or non-K230 host.
    Unknown,
}

/// Best-effort platform detection. Reads `/proc/device-tree/model` to
/// distinguish Avalon K230 home SKUs.
///
/// Unknown K230 boards stay `Unknown`; callers must refuse to drive hardware
/// until a concrete Avalon SKU is identified.
pub fn detect_platform() -> AvalonHomeBoard {
    #[cfg(target_arch = "riscv64")]
    {
        return std::fs::read_to_string("/proc/device-tree/model")
            .map(|s| detect_platform_from_model(&s))
            .unwrap_or(AvalonHomeBoard::Unknown);
    }
    AvalonHomeBoard::Unknown
}

pub fn detect_platform_from_model(model: &str) -> AvalonHomeBoard {
    let compact: String = model
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect();

    if compact.contains("nano3s") {
        AvalonHomeBoard::Nano3s
    } else if compact.contains("nano3") {
        AvalonHomeBoard::Nano3
    } else if compact.contains("mini3") {
        AvalonHomeBoard::Mini3
    } else {
        AvalonHomeBoard::Unknown
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HalError {
    #[error("sysfs path not found: {0}")]
    SysfsMissing(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::{detect_platform_from_model, AvalonHomeBoard};

    #[test]
    fn detects_known_avalon_home_skus_from_model_string() {
        assert_eq!(
            detect_platform_from_model("Canaan Avalon Nano 3S\0"),
            AvalonHomeBoard::Nano3s
        );
        assert_eq!(
            detect_platform_from_model("canaan,avalon-nano-3"),
            AvalonHomeBoard::Nano3
        );
        assert_eq!(
            detect_platform_from_model("Avalon Mini 3 K230"),
            AvalonHomeBoard::Mini3
        );
    }

    #[test]
    fn generic_k230_is_unknown_not_nano3s() {
        assert_eq!(
            detect_platform_from_model("Kendryte K230 CanMV board"),
            AvalonHomeBoard::Unknown
        );
    }
}
