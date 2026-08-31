// SPDX-License-Identifier: GPL-3.0-or-later
//
// Runtime platform detection for DCENT_OS Avalon industrial.
//
// Mirrors the dispatch pattern used by `dcentos/dcentrald/dcentrald-hal/src/platform/mod.rs`
// for Antminer (Zynq vs Amlogic vs BeagleBone). Detection is runtime, not
// compile-time Cargo features. This Linux binary ships for K230 only; K210 is
// retained as a vocabulary marker while its active no_std port stays separate.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // K230Industrial is target-only; K210Industrial is a non-runnable Linux marker
pub enum AvalonIndustrialBoard {
    /// Kendryte K230 — Avalon Q + A14xx/A15xx/A16xx industrial.
    K230Industrial,
    /// Kendryte K210 industrial — separate active no_std firmware lane.
    K210Industrial,
    /// Not running on a recognised Avalon industrial platform.
    Unsupported,
}

/// Best-effort board detection.
///
/// K230 detection: read `/proc/device-tree/model` (or `/proc/cpuinfo`) for
/// `k230` substring + RV64 ISA. K210 industrial doesn't run Linux at all
/// (8 MB SRAM, FreeRTOS), so this fn would never see a K210 host — it returns
/// `Unsupported` everywhere except K230 boxes.
pub fn detect_platform() -> AvalonIndustrialBoard {
    #[cfg(target_arch = "riscv64")]
    {
        if std::fs::read_to_string("/proc/device-tree/model")
            .map(|s| s.to_lowercase().contains("k230"))
            .unwrap_or(false)
        {
            return AvalonIndustrialBoard::K230Industrial;
        }
    }
    AvalonIndustrialBoard::Unsupported
}
